/*
 *  alpm.c
 * 
 *  Copyright (c) 2002 by Judd Vinet <jvinet@zeroflux.org>
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, 
 *  USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <limits.h> /* PATH_MAX */
#include <stdarg.h>
/* pacman */
#include "log.h"
#include "error.h"
#include "versioncmp.h"
#include "md5.h"
#include "sha1.h"
#include "list.h"
#include "package.h"
#include "group.h"
#include "util.h"
#include "db.h"
#include "cache.h"
#include "deps.h"
#include "backup.h"
#include "add.h"
#include "remove.h"
#include "sync.h"
#include "handle.h"
#include "provide.h"
#include "alpm.h"

#define PM_LOCK   "/tmp/pacman.lck"

/* Globals */
pmhandle_t *handle = NULL;
enum __pmerrno_t pm_errno;

/** @defgroup alpm_interface Interface Functions
 * @{
 */

/** Initializes the library.  This must be called before any other
 * functions are called.
 * @param root the full path of the root we'll be installing to (usually /)
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_initialize(char *root)
{
	char str[PATH_MAX];

	ASSERT(handle == NULL, RET_ERR(PM_ERR_HANDLE_NOT_NULL, -1));

	handle = handle_new();
	if(handle == NULL) {
		RET_ERR(PM_ERR_MEMORY, -1);
	}

	/* lock db */
	if(handle->access == PM_ACCESS_RW) {
		handle->lckfd = _alpm_lckmk(PM_LOCK);
		if(handle->lckfd == -1) {
			FREE(handle);
			RET_ERR(PM_ERR_HANDLE_LOCK, -1);
		}
	}

	STRNCPY(str, (root) ? root : PM_ROOT, PATH_MAX);
	/* add a trailing '/' if there isn't one */
	if(str[strlen(str)-1] != '/') {
		strcat(str, "/");
	}
	handle->root = strdup(str);

	return(0);
}

/** Release the library.  This should be the last alpm call you make.
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_release()
{
	PMList *i;

	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));

	/* unlock db */
	if(handle->access == PM_ACCESS_RW) {
		if(handle->lckfd != -1) {
			close(handle->lckfd);
			handle->lckfd = -1;
		}
		if(_alpm_lckrm(PM_LOCK)) {
			_alpm_log(PM_LOG_WARNING, "could not remove lock file %s", PM_LOCK);
			alpm_logaction("warning: could not remove lock file %s", PM_LOCK);
		}
	}

	/* close local database */
	if(handle->db_local) {
		db_close(handle->db_local);
		handle->db_local = NULL;
	}
	/* and also sync ones */
	for(i = handle->dbs_sync; i; i = i->next) {
		db_close(i->data);
		i->data = NULL;
	}

	FREEHANDLE(handle);

	return(0);
}
/** @} */

/** @defgroup alpm_options Library Options
 * @{
 */

/** Set a library option.
 * @param parm the name of the parameter
 * @param data the value of the parameter
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_set_option(unsigned char parm, unsigned long data)
{
	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));

	return(handle_set_option(handle, parm, data));
}

/** Get the value of a library option.
 * @param parm the parameter to get
 * @param data pointer argument to get the value in
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_get_option(unsigned char parm, long *data)
{
	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));
	ASSERT(data != NULL, RET_ERR(PM_ERR_WRONG_ARGS, -1));

	return(handle_get_option(handle, parm, data));
}
/** @} */

/** @defgroup alpm_databases Database Functions
 * @{
 */

/** Register a package database
 * @param treename the name of the repository
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
pmdb_t *alpm_db_register(char *treename)
{
	pmdb_t *db;
	int found = 0;

	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, NULL));
	ASSERT(treename != NULL && strlen(treename) != 0, RET_ERR(PM_ERR_WRONG_ARGS, NULL));
	/* Do not register a database if a transaction is on-going */
	ASSERT(handle->trans == NULL, RET_ERR(PM_ERR_TRANS_NOT_NULL, NULL));

	if(strcmp(treename, "local") == 0) {
		if(handle->db_local != NULL) {
			found = 1;
		}
	} else {
		PMList *i;
		for(i = handle->dbs_sync; i && !found; i = i->next) {
			pmdb_t *sdb = i->data;
			if(strcmp(treename, sdb->treename) == 0) {
				found = 1;
			}
		}
	}
	if(found) {
		RET_ERR(PM_ERR_DB_NOT_NULL, NULL);
	}

	db = db_open(handle->root, handle->dbpath, treename);
	if(db == NULL) {
		/* couldn't open the db directory - try creating it */
		if(db_create(handle->root, handle->dbpath, treename) == -1) {
			RET_ERR(PM_ERR_DB_CREATE, NULL);
		}
		db = db_open(handle->root, handle->dbpath, treename);
		if(db == NULL) {
			/* couldn't open the db directory */
			RET_ERR(PM_ERR_DB_OPEN, NULL);
		}
	}

	if(strcmp(treename, "local") == 0) {
		handle->db_local = db;
	} else {
		handle->dbs_sync = pm_list_add(handle->dbs_sync, db);
	}

	return(db);
}

/** Helper function for comparing databases
 * @param db1 first database
 * @param db2 second database
 * @return an integer less than, equal to, or greater than zero if the name of
 * db1 is found, respectively, to be less than, to match, or be greater than
 * the name of db2.
 */
static int db_cmp(const void *db1, const void *db2)
{
	return(strcmp(((pmdb_t *)db1)->treename, ((pmdb_t *)db2)->treename));
}

/** Unregister a package database
 * @param db pointer to the package database to unregister
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_db_unregister(pmdb_t *db)
{
	int found = 0;

	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));
	ASSERT(db != NULL, RET_ERR(PM_ERR_WRONG_ARGS, -1));
	/* Do not unregister a database if a transaction is on-going */
	ASSERT(handle->trans == NULL, RET_ERR(PM_ERR_TRANS_NOT_NULL, -1));

	if(db == handle->db_local) {
		db_close(handle->db_local);
		handle->db_local = NULL;
		found = 1;
	} else {
		pmdb_t *data;
		handle->dbs_sync = _alpm_list_remove(handle->dbs_sync, db, db_cmp, (void **)&data);
		if(data) {
			db_close(data);
			found = 1;
		}
	}

	if(!found) {
		RET_ERR(PM_ERR_DB_NOT_FOUND, -1);
	}

	return(0);
}

/** Get informations about a database.
 * @param db database pointer
 * @param parm name of the info to get
 * @return a char* on success (the value), NULL on error
 */
void *alpm_db_getinfo(PM_DB *db, unsigned char parm)
{
	void *data = NULL;

	/* Sanity checks */
	ASSERT(handle != NULL, return(NULL));
	ASSERT(db != NULL, return(NULL));

	switch(parm) {
		case PM_DB_TREENAME:   data = db->treename; break;
		case PM_DB_LASTUPDATE: data = db->lastupdate; break;
		default:
			data = NULL;
	}

	return(data);
}

/** Update a package database
 * @param db pointer to the package database to update
 * @param archive path to the new package database tarball
 * @param ts timestamp of the last modification time of the tarball
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_db_update(PM_DB *db, char *archive, char *ts)
{
	PMList *lp;

	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));
	ASSERT(db != NULL && db != handle->db_local, RET_ERR(PM_ERR_WRONG_ARGS, -1));
	/* Do not update a database if a transaction is on-going */
	ASSERT(handle->trans == NULL, RET_ERR(PM_ERR_TRANS_NOT_NULL, -1));

	if(!pm_list_is_in(db, handle->dbs_sync)) {
		RET_ERR(PM_ERR_DB_NOT_FOUND, -1);
	}

	if(ts && strlen(ts) != 0) {
		if(strcmp(ts, db->lastupdate) == 0) {
			RET_ERR(PM_ERR_DB_UPTODATE, -1);
		}
	}

	/* remove the old dir */
	_alpm_log(PM_LOG_FLOW2, "flushing database %s/%s", handle->dbpath, db->treename);
	for(lp = db_get_pkgcache(db); lp; lp = lp->next) {
		if(db_remove(db, lp->data) == -1) {
			if(lp->data) {
				_alpm_log(PM_LOG_ERROR, "could not remove database entry %s/%s", db->treename,
				                        ((pmpkg_t *)lp->data)->name);
			}
			RET_ERR(PM_ERR_XXX, -1);
		}
	}

	/* Cache needs to be rebuild */
	db_free_pkgcache(db);

	/* uncompress the sync database */
	/* ORE
	we should not simply unpack the archive, but better parse it and 
	db_write each entry (see sync_load_dbarchive to get archive content) */
	_alpm_log(PM_LOG_FLOW2, "unpacking %s", archive);
	if(_alpm_unpack(archive, db->path, NULL)) {
		RET_ERR(PM_ERR_XXX, -1);
	}

	if(ts && strlen(ts) != 0) {
		if(db_setlastupdate(db, ts) == -1) {
			RET_ERR(PM_ERR_XXX, -1);
		}
	}

	return(0);
}

/** Get a package entry from a package database
 * @param db pointer to the package database to get the package from
 * @param name of the package
 * @return the package entry on success, NULL on error
 */
pmpkg_t *alpm_db_readpkg(pmdb_t *db, char *name)
{
	/* Sanity checks */
	ASSERT(handle != NULL, return(NULL));
	ASSERT(db != NULL, return(NULL));
	ASSERT(name != NULL && strlen(name) != 0, return(NULL));

	return(db_get_pkgfromcache(db, name));
}

/** Get the package cache of a package database
 * @param db pointer to the package database to get the package from
 * @return the list of packages on success, NULL on error
 */
PMList *alpm_db_getpkgcache(pmdb_t *db)
{
	/* Sanity checks */
	ASSERT(handle != NULL, return(NULL));
	ASSERT(db != NULL, return(NULL));

	return(db_get_pkgcache(db));
}

/** Get the list of packages that a package provides
 * @param db pointer to the package database to get the package from
 * @param name name of the package
 * @return the list of packages on success, NULL on error
 */
PMList *alpm_db_whatprovides(pmdb_t *db, char *name)
{
	/* Sanity checks */
	ASSERT(handle != NULL, return(NULL));
	ASSERT(db != NULL, return(NULL));
	ASSERT(name != NULL && strlen(name) != 0, return(NULL));

	return(_alpm_db_whatprovides(db, name));
}

/** Get a group entry from a package database
 * @param db pointer to the package database to get the group from
 * @param name of the group
 * @return the groups entry on success, NULL on error
 */
pmgrp_t *alpm_db_readgrp(pmdb_t *db, char *name)
{
	/* Sanity checks */
	ASSERT(handle != NULL, return(NULL));
	ASSERT(db != NULL, return(NULL));
	ASSERT(name != NULL && strlen(name) != 0, return(NULL));

	return(db_get_grpfromcache(db, name));
}

/** Get the group cache of a package database
 * @param db pointer to the package database to get the group from
 * @return the list of groups on success, NULL on error
 */
PMList *alpm_db_getgrpcache(pmdb_t *db)
{
	/* Sanity checks */
	ASSERT(handle != NULL, return(NULL));
	ASSERT(db != NULL, return(NULL));

	return(db_get_grpcache(db));
}
/** @} */

/** @defgroup alpm_packages Package Functions
 * @{
 */

/** Get informations about a package.
 * @param db package pointer
 * @param parm name of the info to get
 * @return a char* on success (the value), NULL on error
 */
void *alpm_pkg_getinfo(pmpkg_t *pkg, unsigned char parm)
{
	void *data = NULL;

	/* Sanity checks */
	ASSERT(handle != NULL, return(NULL));
	ASSERT(pkg != NULL, return(NULL));

	/* Update the cache package entry if needed */
	if(pkg->origin == PKG_FROM_CACHE) {
		switch(parm) {
			/* Desc entry */
			case PM_PKG_NAME:
			case PM_PKG_VERSION:
			case PM_PKG_DESC:
			case PM_PKG_GROUPS:
			case PM_PKG_URL:
			case PM_PKG_LICENSE:
			case PM_PKG_ARCH:
			case PM_PKG_BUILDDATE:
			case PM_PKG_INSTALLDATE:
			case PM_PKG_PACKAGER:
			case PM_PKG_SIZE:
			case PM_PKG_REASON:
			case PM_PKG_MD5SUM:
			case PM_PKG_SHA1SUM:
				if(!(pkg->infolevel & INFRQ_DESC)) {
					char target[PKG_FULLNAME_LEN];
					snprintf(target, PKG_FULLNAME_LEN, "%s-%s", pkg->name, pkg->version);
					db_read(pkg->data, target, INFRQ_DESC, pkg);
				}
			break;
			/* Depends entry */
			/* not needed: the cache is loaded with DEPENDS by default
			case PM_PKG_DEPENDS:
			case PM_PKG_REQUIREDBY:
			case PM_PKG_CONFLICTS:
			case PM_PKG_PROVIDES:
			case PM_PKG_REPLACES:
				if(!(pkg->infolevel & INFRQ_DEPENDS)) {
					char target[PKG_FULLNAME_LEN];
					snprintf(target, PKG_FULLNAME_LEN, "%s-%s", pkg->name, pkg->version);
					db_read(pkg->data, target, INFRQ_DEPENDS, pkg);
				}
			break;*/
			/* Files entry */
			case PM_PKG_FILES:
			case PM_PKG_BACKUP:
				if(pkg->data == handle->db_local && !(pkg->infolevel & INFRQ_FILES)) {
					char target[PKG_FULLNAME_LEN];
					snprintf(target, PKG_FULLNAME_LEN, "%s-%s", pkg->name, pkg->version);
					db_read(pkg->data, target, INFRQ_FILES, pkg);
				}
			break;
			/* Scriptlet */
			case PM_PKG_SCRIPLET:
				if(pkg->data == handle->db_local && !(pkg->infolevel & INFRQ_SCRIPLET)) {
					char target[PKG_FULLNAME_LEN];
					snprintf(target, PKG_FULLNAME_LEN, "%s-%s", pkg->name, pkg->version);
					db_read(pkg->data, target, INFRQ_SCRIPLET, pkg);
				}
			break;
		}
	}

	switch(parm) {
		case PM_PKG_NAME:        data = pkg->name; break;
		case PM_PKG_VERSION:     data = pkg->version; break;
		case PM_PKG_DESC:        data = pkg->desc; break;
		case PM_PKG_GROUPS:      data = pkg->groups; break;
		case PM_PKG_URL:         data = pkg->url; break;
		case PM_PKG_ARCH:        data = pkg->arch; break;
		case PM_PKG_BUILDDATE:   data = pkg->builddate; break;
		case PM_PKG_INSTALLDATE: data = pkg->installdate; break;
		case PM_PKG_PACKAGER:    data = pkg->packager; break;
		case PM_PKG_SIZE:        data = (void *)pkg->size; break;
		case PM_PKG_REASON:      data = (void *)(int)pkg->reason; break;
		case PM_PKG_LICENSE:     data = pkg->license; break;
		case PM_PKG_REPLACES:    data = pkg->replaces; break;
		case PM_PKG_MD5SUM:      data = pkg->md5sum; break;
		case PM_PKG_SHA1SUM:     data = pkg->sha1sum; break;
		case PM_PKG_DEPENDS:     data = pkg->depends; break;
		case PM_PKG_REMOVES:     data = pkg->removes; break;
		case PM_PKG_REQUIREDBY:  data = pkg->requiredby; break;
		case PM_PKG_PROVIDES:    data = pkg->provides; break;
		case PM_PKG_CONFLICTS:   data = pkg->conflicts; break;
		case PM_PKG_FILES:       data = pkg->files; break;
		case PM_PKG_BACKUP:      data = pkg->backup; break;
		case PM_PKG_SCRIPLET:    data = (void *)(int)pkg->scriptlet; break;
		case PM_PKG_DATA:        data = pkg->data; break;
		default:
			data = NULL;
		break;
	}

	return(data);
}

/** Create a package from a file.
 * @param filename location of the package tarball
 * @param pkg address of the package pointer
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_pkg_load(char *filename, pmpkg_t **pkg)
{
	/* Sanity checks */
	ASSERT(filename != NULL && strlen(filename) != 0, RET_ERR(PM_ERR_WRONG_ARGS, -1));
	ASSERT(pkg != NULL, RET_ERR(PM_ERR_WRONG_ARGS, -1));

	*pkg = pkg_load(filename);
	if(*pkg == NULL) {
		/* pm_errno is set by pkg_load */
		return(-1);
	}

	return(0);
}

/** Free a package.
 * @param pkg package pointer to free
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_pkg_free(pmpkg_t *pkg)
{
	ASSERT(pkg != NULL, RET_ERR(PM_ERR_WRONG_ARGS, -1));
	ASSERT(pkg->origin != PKG_FROM_CACHE, RET_ERR(PM_ERR_XXX, -1));

	pkg_free(pkg);

	return(0);
}

/** Compare versions.
 * @param ver1 first version
 * @param ver2 secont version
 * @return postive, 0 or negative if ver1 is less, equal or more
 * than ver2, respectively.
 */
int alpm_pkg_vercmp(const char *ver1, const char *ver2)
{
	return(versioncmp(ver1, ver2));
}
/** @} */

/** @defgroup alpm_groups Group Functions
 * @{
 */

/** Get informations about a group.
 * @param grp group pointer
 * @param parm name of the info to get
 * @return a char* on success (the value), NULL on error
 */
void *alpm_grp_getinfo(pmgrp_t *grp, unsigned char parm)
{
	void *data = NULL;

	/* Sanity checks */
	ASSERT(grp != NULL, return(NULL));

	switch(parm) {
		case PM_GRP_NAME:     data = grp->name; break;
		case PM_GRP_PKGNAMES: data = grp->packages; break;
		default:
			data = NULL;
		break;
	}

	return(data);
}
/** @} */

/** @defgroup alpm_sync Sync Functions
 * @{
 */

/** Get informations about a sync.
 * @param sync pointer
 * @param parm name of the info to get
 * @return a char* on success (the value), NULL on error
 */
void *alpm_sync_getinfo(pmsyncpkg_t *sync, unsigned char parm)
{
	void *data;

	/* Sanity checks */
	ASSERT(sync != NULL, return(NULL));

	switch(parm) {
		case PM_SYNC_TYPE: data = (void *)(int)sync->type; break;
		case PM_SYNC_PKG:  data = sync->pkg; break;
		case PM_SYNC_DATA: data = sync->data; break;
		default:
			data = NULL;
		break;
	}

	return(data);
}
/** @} */

/** @defgroup alpm_trans Transaction Functions
 * @{
 */

/** Get informations about the transaction.
 * @param parm name of the info to get
 * @return a char* on success (the value), NULL on error
 */
void *alpm_trans_getinfo(unsigned char parm)
{
	pmtrans_t *trans;
	void *data;

	/* Sanity checks */
	ASSERT(handle != NULL, return(NULL));
	ASSERT(handle->trans != NULL, return(NULL));

	trans = handle->trans;

	switch(parm) {
		case PM_TRANS_TYPE:     data = (void *)(int)trans->type; break;
		case PM_TRANS_FLAGS:    data = (void *)(int)trans->flags; break;
		case PM_TRANS_TARGETS:  data = trans->targets; break;
		case PM_TRANS_PACKAGES: data = trans->packages; break;
		default:
			data = NULL;
		break;
	}

	return(data);
}

/** Initialize the transaction.
 * @param type type of the transaction
 * @param flags flags of the transaction (like nodeps, etc)
 * @param event event callback function pointer
 * @param conv question callback function pointer
 * @param progress progress callback function pointer
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_trans_init(unsigned char type, unsigned int flags, alpm_trans_cb_event event, alpm_trans_cb_conv conv, alpm_trans_cb_progress progress)
{
	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));

	ASSERT(handle->trans == NULL, RET_ERR(PM_ERR_TRANS_NOT_NULL, -1));

	handle->trans = trans_new();
	if(handle->trans == NULL) {
		RET_ERR(PM_ERR_MEMORY, -1);
	}

	return(trans_init(handle->trans, type, flags, event, conv, progress));
}

/** Search for packages to upgrade and add them to the transaction.
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_trans_sysupgrade()
{
	pmtrans_t *trans;

	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));

	trans = handle->trans;
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->state == STATE_INITIALIZED, RET_ERR(PM_ERR_TRANS_NOT_INITIALIZED, -1));
	ASSERT(trans->type == PM_TRANS_TYPE_SYNC, RET_ERR(PM_ERR_XXX, -1));

	return(trans_sysupgrade(trans));
}

/** Add a target to the transaction.
 * @param target the name of the target to add
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_trans_addtarget(char *target)
{
	pmtrans_t *trans;

	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));
	ASSERT(target != NULL && strlen(target) != 0, RET_ERR(PM_ERR_WRONG_ARGS, -1));

	trans = handle->trans;
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->state == STATE_INITIALIZED, RET_ERR(PM_ERR_TRANS_NOT_INITIALIZED, -1));

	return(trans_addtarget(trans, target));
}

/** Prepare a transaction.
 * @param data the address of a PM_LIST where detailed description
 * of an error can be dumped (ie. list of conflicting files)
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_trans_prepare(PMList **data)
{
	pmtrans_t *trans;

	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));
	ASSERT(data != NULL, RET_ERR(PM_ERR_WRONG_ARGS, -1));

	trans = handle->trans;
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->state == STATE_INITIALIZED, RET_ERR(PM_ERR_TRANS_NOT_INITIALIZED, -1));

	return(trans_prepare(handle->trans, data));
}

/** Commit a transaction.
 * @param data the address of a PM_LIST where detailed description
 * of an error can be dumped (ie. list of conflicting files)
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_trans_commit(PMList **data)
{
	pmtrans_t *trans;

	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));

	trans = handle->trans;
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->state == STATE_PREPARED, RET_ERR(PM_ERR_TRANS_NOT_PREPARED, -1));

	/* Check for database R/W permission */
	ASSERT(handle->access == PM_ACCESS_RW, RET_ERR(PM_ERR_BADPERMS, -1));

	return(trans_commit(handle->trans, data));
}

/** Release a transaction.
 * @return 0 on success, -1 on error (pm_errno is set accordingly)
 */
int alpm_trans_release()
{
	pmtrans_t *trans;

	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));

	trans = handle->trans;
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->state != STATE_IDLE, RET_ERR(PM_ERR_TRANS_NULL, -1));

	FREETRANS(handle->trans);

	return(0);
}
/** @} */

/** @defgroup alpm_dep Dependency Functions
 * @{
 */

void *alpm_dep_getinfo(pmdepmissing_t *miss, unsigned char parm)
{
	void *data;

	/* Sanity checks */
	ASSERT(miss != NULL, return(NULL));

	switch(parm) {
		case PM_DEP_TARGET:  data = (void *)(int)miss->target; break;
		case PM_DEP_TYPE:    data = (void *)(int)miss->type; break;
		case PM_DEP_MOD:     data = (void *)(int)miss->depend.mod; break;
		case PM_DEP_NAME:    data = miss->depend.name; break;
		case PM_DEP_VERSION: data = miss->depend.version; break;
		default:
			data = NULL;
		break;
	}

	return(data);
}
/** @} */

/** @defgroup alpm_log Logging Functions
 * @{
 */

int alpm_logaction(char *fmt, ...)
{
	char str[LOG_STR_LEN];
	va_list args;

	/* Sanity checks */
	ASSERT(handle != NULL, RET_ERR(PM_ERR_HANDLE_NULL, -1));

	va_start(args, fmt);
	vsnprintf(str, LOG_STR_LEN, fmt, args);
	va_end(args);

	/* ORE
	We should add a prefix to log strings depending on who called us.
	If logaction was called by the frontend:
		USER: <the frontend log>
	and if called internally:
		ALPM: <the library log>
	Moreover, the frontend should be able to choose its prefix (USER by default?):
		pacman: "PACMAN"
		kpacman: "KPACMAN"
		...
	It allows to share the log file between several frontends and to actually 
	know who does what */

	return(_alpm_logaction(handle->usesyslog, handle->logfd, str));
}
/** @} */

/** @defgroup alpm_list List Manipulation Functions
 * @{
 */

PMList *alpm_list_first(PMList *list)
{
	return(list);
}

PMList *alpm_list_next(PMList *entry)
{
	ASSERT(entry != NULL, return(NULL));

	return(entry->next);
}

void *alpm_list_getdata(PMList *entry)
{
	ASSERT(entry != NULL, return(NULL));

	return(entry->data);
}

int alpm_list_free(PMList *entry)
{
	ASSERT(entry != NULL, return(-1));

	FREELIST(entry);

	return(0);
}

int alpm_list_count(PMList *list)
{
	ASSERT(list != NULL, return(NULL));

	return(_alpm_list_count(list));
}
/** @} */

/** @defgroup alpm_misc Miscellaneous Functions
 * @{
 */

char *alpm_get_md5sum(char *name)
{
	ASSERT(name != NULL, return(NULL));

	return(MDFile(name));
}

char *alpm_get_sha1sum(char *name)
{
	ASSERT(name != NULL, return(NULL));

	return(SHAFile(name));
}
/* @} */

/* vim: set ts=2 sw=2 noet: */

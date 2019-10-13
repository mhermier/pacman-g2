/*
 *  add.c
 *
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2005 by Christian Hamar <krics@linuxforum.hu>
 *  Copyright (c) 2006 by David Kimpe <dnaku@frugalware.org>
 *  Copyright (c) 2005, 2006 by Miklos Vajna <vmiklos@frugalware.org>
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

#if defined(__APPLE__) || defined(__OpenBSD__)
#include <sys/syslimits.h>
#endif
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__sun__)
#include <sys/stat.h>
#endif

#include "config.h"
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <libintl.h>
/* pacman-g2 */
#include "list.h"
#include "trans.h"
#include "util.h"
#include "error.h"
#include "cache.h"
#include "deps.h"
#include "versioncmp.h"
#include "md5.h"
#include "sha1.h"
#include "log.h"
#include "backup.h"
#include "package.h"
#include "db.h"
#include "provide.h"
#include "conflict.h"
#include "add.h"
#include "remove.h"
#include "handle.h"
#include "packages_transaction.h"

static int add_faketarget(pmtrans_t *trans, const char *name)
{
	char *ptr, *p;
	char *str = NULL;
	pmpkg_t *dummy = NULL;

	dummy = _pacman_pkg_new(NULL, NULL);
	if(dummy == NULL) {
		RET_ERR(PM_ERR_MEMORY, -1);
	}

	/* Format: field1=value1|field2=value2|...
	 * Valid fields are "name", "version" and "depend"
	 */
	str = strdup(name);
	ptr = str;
	while((p = strsep(&ptr, "|")) != NULL) {
		char *q;
		if(p[0] == 0) {
			continue;
		}
		q = strchr(p, '=');
		if(q == NULL) { /* not a valid token */
			continue;
		}
		if(strncmp("name", p, q-p) == 0) {
			STRNCPY(dummy->name, q+1, PKG_NAME_LEN);
		} else if(strncmp("version", p, q-p) == 0) {
			STRNCPY(dummy->version, q+1, PKG_VERSION_LEN);
		} else if(strncmp("depend", p, q-p) == 0) {
			dummy->depends = _pacman_list_add(dummy->depends, strdup(q+1));
		} else {
			_pacman_log(PM_LOG_ERROR, _("could not parse token %s"), p);
		}
	}
	FREE(str);
	if(dummy->name[0] == 0 || dummy->version[0] == 0) {
		FREEPKG(dummy);
		RET_ERR(PM_ERR_PKG_INVALID_NAME, -1);
	}

	/* add the package to the transaction */
	trans->packages = _pacman_list_add(trans->packages, dummy);

	return(0);
}

int _pacman_add_addtarget(pmtrans_t *trans, const char *name)
{
	pmpkg_t *info = NULL;
	pmlist_t *i;
	pmpkg_t *local;
	struct stat buf;
	pmdb_t *db = trans->handle->db_local;

	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(db != NULL, RET_ERR(PM_ERR_DB_NULL, -1));
	ASSERT(name != NULL && strlen(name) != 0, RET_ERR(PM_ERR_WRONG_ARGS, -1));

	/* Check if we need to add a fake target to the transaction. */
	if(strchr(name, '|')) {
		return(add_faketarget(trans, name));
	}

	if(stat(name, &buf)) {
		pm_errno = PM_ERR_NOT_A_FILE;
		goto error;
	}

	_pacman_log(PM_LOG_FLOW2, _("loading target '%s'"), name);
	info = _pacman_pkg_load(name);
	if(info == NULL) {
		/* pm_errno is already set by pkg_load() */
		goto error;
	}

	/* no additional hyphens in version strings */
	if(strchr(_pacman_pkg_getinfo(info, PM_PKG_VERSION), '-') !=
			strrchr(_pacman_pkg_getinfo(info, PM_PKG_VERSION), '-')) {
		pm_errno = PM_ERR_PKG_INVALID_NAME;
		goto error;
	}

	local = _pacman_db_get_pkgfromcache(db, info->name);

	if(trans->type != PM_TRANS_TYPE_UPGRADE) {
		/* only install this package if it is not already installed */
		if(local != NULL) {
			pm_errno = PM_ERR_PKG_INSTALLED;
			goto error;
		}
	} else {
		if(trans->flags & PM_TRANS_FLAG_FRESHEN) {
			/* only upgrade/install this package if it is already installed and at a lesser version */
			if(local == NULL || _pacman_versioncmp(local->version, info->version) >= 0) {
				pm_errno = PM_ERR_PKG_CANT_FRESH;
				goto error;
			}
		}
	}

	/* check if an older version of said package is already in transaction packages.
	 * if so, replace it in the list */
	for(i = trans->packages; i; i = i->next) {
		pmpkg_t *pkg = i->data;
		if(strcmp(pkg->name, _pacman_pkg_getinfo(info, PM_PKG_NAME)) == 0) {
			if(_pacman_versioncmp(pkg->version, info->version) < 0) {
				pmpkg_t *newpkg;
				_pacman_log(PM_LOG_WARNING, _("replacing older version %s-%s by %s in target list"),
				          pkg->name, pkg->version, info->version);
				if((newpkg = _pacman_pkg_load(name)) == NULL) {
					/* pm_errno is already set by pkg_load() */
					goto error;
				}
				FREEPKG(i->data);
				i->data = newpkg;
			} else {
				_pacman_log(PM_LOG_WARNING, _("newer version %s-%s is in the target list -- skipping"),
				          pkg->name, pkg->version, info->version);
			}
			return(0);
		}
	}

	if(trans->flags & PM_TRANS_FLAG_ALLDEPS) {
		info->reason = PM_PKG_REASON_DEPEND;
	}

	/* copy over the install reason */
	if(local) {
		info->reason = (long)_pacman_pkg_getinfo(local, PM_PKG_REASON);
	}

	/* add the package to the transaction */
	trans->packages = _pacman_list_add(trans->packages, info);

	return(0);

error:
	FREEPKG(info);
	return(-1);
}

int _pacman_add_prepare(pmtrans_t *trans, pmlist_t **data)
{
	pmlist_t *lp;
	pmlist_t *rmlist = NULL;
	char rm_fname[PATH_MAX];
	pmpkg_t *info = NULL;
	pmdb_t *db = trans->handle->db_local;

	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(db != NULL, RET_ERR(PM_ERR_DB_NULL, -1));

	/* Check dependencies
	 */
	if(!(trans->flags & PM_TRANS_FLAG_NODEPS)) {
		EVENT(trans, PM_TRANS_EVT_CHECKDEPS_START, NULL, NULL);

		/* look for unsatisfied dependencies */
		_pacman_log(PM_LOG_FLOW1, _("looking for unsatisfied dependencies"));
		lp = _pacman_checkdeps(trans, db, trans->type, trans->packages);
		if(lp != NULL) {
			if(data) {
				*data = lp;
			} else {
				FREELIST(lp);
			}
			RET_ERR(PM_ERR_UNSATISFIED_DEPS, -1);
		}

		/* no unsatisfied deps, so look for conflicts */
		_pacman_log(PM_LOG_FLOW1, _("looking for conflicts"));
		lp = _pacman_checkconflicts(trans, db, trans->packages);
		if(lp != NULL) {
			if(data) {
				*data = lp;
			} else {
				FREELIST(lp);
			}
			RET_ERR(PM_ERR_CONFLICTING_DEPS, -1);
		}

		/* re-order w.r.t. dependencies */
		_pacman_log(PM_LOG_FLOW1, _("sorting by dependencies"));
		lp = _pacman_sortbydeps(trans->packages, PM_TRANS_TYPE_ADD);
		/* free the old alltargs */
		FREELISTPTR(trans->packages);
		trans->packages = lp;

		EVENT(trans, PM_TRANS_EVT_CHECKDEPS_DONE, NULL, NULL);
	}

	/* Cleaning up
	 */
	EVENT(trans, PM_TRANS_EVT_CLEANUP_START, NULL, NULL);
	_pacman_log(PM_LOG_FLOW1, _("cleaning up"));
	for (lp=trans->packages; lp!=NULL; lp=lp->next) {
		info=(pmpkg_t *)lp->data;
		for (rmlist=info->removes; rmlist!=NULL; rmlist=rmlist->next) {
			snprintf(rm_fname, PATH_MAX, "%s%s", handle->root, (char *)rmlist->data);
			remove(rm_fname);
		}
	}
	EVENT(trans, PM_TRANS_EVT_CLEANUP_DONE, NULL, NULL);

	/* Check for file conflicts
	 */
	if(!(trans->flags & PM_TRANS_FLAG_FORCE)) {
		pmlist_t *skiplist = NULL;

		EVENT(trans, PM_TRANS_EVT_FILECONFLICTS_START, NULL, NULL);

		_pacman_log(PM_LOG_FLOW1, _("looking for file conflicts"));
		lp = _pacman_db_find_conflicts(db, trans, &skiplist);
		if(lp != NULL) {
			if(data) {
				*data = lp;
			} else {
				FREELIST(lp);
			}
			FREELIST(skiplist);
			RET_ERR(PM_ERR_FILE_CONFLICTS, -1);
		}

		/* copy the file skiplist into the transaction */
		trans->skiplist = skiplist;

		EVENT(trans, PM_TRANS_EVT_FILECONFLICTS_DONE, NULL, NULL);
	}

#ifndef __sun__
	if(_pacman_check_freespace(trans, data) == -1) {
			/* pm_errno is set by check_freespace */
			return(-1);
	}
#endif

	return(0);
}

const pmtrans_ops_t _pacman_add_pmtrans_opts = {
	.addtarget = _pacman_add_addtarget,
	.prepare = _pacman_add_prepare,
	.commit = _pacman_add_commit
};

/* vim: set ts=2 sw=2 noet: */

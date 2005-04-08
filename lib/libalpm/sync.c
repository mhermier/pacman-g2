/*
 *  sync.c
 * 
 *  Copyright (c) 2002-2005 by Judd Vinet <jvinet@zeroflux.org>
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

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <libtar.h>
#include <zlib.h>
/* pacman */
#include "log.h"
#include "util.h"
#include "error.h"
#include "list.h"
#include "package.h"
#include "db.h"
#include "cache.h"
#include "deps.h"
#include "trans.h"
#include "sync.h"
#include "rpmvercmp.h"
#include "handle.h"

extern pmhandle_t *handle;

pmsyncpkg_t *sync_new(int type, pmpkg_t *lpkg, pmpkg_t *spkg)
{
	pmsyncpkg_t *sync;

	if((sync = (pmsyncpkg_t *)malloc(sizeof(pmsyncpkg_t))) == NULL) {
		return(NULL);
	}

	sync->type = type;
	sync->lpkg = lpkg;
	sync->spkg = spkg;
	sync->replaces = NULL;
	
	return(sync);
}

void sync_free(pmsyncpkg_t *sync)
{
	if(sync) {
		FREELISTPTR(sync->replaces);
		free(sync);
	}
}

/* Test for existance of a package in a PMList* of pmsyncpkg_t*
 * If found, return a pointer to the respective pmsyncpkg_t*
 */
static pmsyncpkg_t* find_pkginsync(char *needle, PMList *haystack)
{
	PMList *i;
	pmsyncpkg_t *sync = NULL;
	int found = 0;

	for(i = haystack; i && !found; i = i->next) {
		sync = i->data;
		if(sync && !strcmp(sync->spkg->name, needle)) {
			found = 1;
		}
	}
	if(!found) {
		sync = NULL;
	}

	return(sync);
}

/* It returns a PMList of packages extracted from the given archive
 * (the archive must have been generated by gensync)
 */
PMList *sync_load_archive(char *archive)
{
	PMList *lp = NULL;
	DIR *dir = NULL;
	TAR *tar = NULL;
	tartype_t gztype = {
		(openfunc_t)_alpm_gzopen_frontend,
		(closefunc_t)gzclose,
		(readfunc_t)gzread,
		(writefunc_t)gzwrite
	};

	if(tar_open(&tar, archive, &gztype, O_RDONLY, 0, TAR_GNU) == -1) {
		pm_errno = PM_ERR_NOT_A_FILE;
		goto error;
	}

	/* readdir tmp_dir */
	/* for each subdir, parse %s/desc and %s/depends */

	tar_close(tar);

	return(lp);

error:
	if(tar) {
		tar_close(tar);
	}
	if(dir) {
		closedir(dir);
	}
	return(NULL);
}

int sync_sysupgrade(PMList **data)
{
	PMList *i, *j, *k;
	PMList *targets = NULL;

	*data = NULL;

	/* check for "recommended" package replacements */
	for(i = handle->dbs_sync; i; i = i->next) {
		PMList *j;

		for(j = db_get_pkgcache(i->data); j; j = j->next) {
			pmpkg_t *spkg = j->data;

			for(k = spkg->replaces; k; k = k->next) {
				PMList *m;

				for(m = db_get_pkgcache(handle->db_local); m; m = m->next) {
					pmpkg_t *lpkg = m->data;

					if(!strcmp(k->data, lpkg->name)) {
						if(pm_list_is_strin(lpkg->name, handle->ignorepkg)) {
							_alpm_log(PM_LOG_WARNING, "%s-%s: ignoring package upgrade (to be replaced by %s-%s)",
								lpkg->name, lpkg->version, spkg->name, spkg->version);
						} else {
							pmsyncpkg_t *sync = sync_new(PM_SYNC_TYPE_REPLACE, lpkg, spkg);
							if(sync == NULL) {
								pm_errno = PM_ERR_MEMORY;
								goto error;
							}
							_alpm_log(PM_LOG_DEBUG, "%s-%s elected for upgrade (to be replaced by %s-%s)",
							          lpkg->name, lpkg->version, spkg->name, spkg->version);
							targets = pm_list_add(targets, sync);
						}
					}
				}
			}
		}
	}

	/* match installed packages with the sync dbs and compare versions */
	for(i = db_get_pkgcache(handle->db_local); i; i = i->next) {
		int cmp;
		pmpkg_t *local = i->data;
		pmpkg_t *spkg = NULL;
		pmsyncpkg_t *sync;

		for(j = handle->dbs_sync; !spkg && j; j = j->next) {

			for(k = db_get_pkgcache(j->data); !spkg && k; k = k->next) {
				pmpkg_t *sp = k->data;
				if(!strcmp(local->name, sp->name)) {
					spkg = sp;
				}
			}
		}
		if(spkg == NULL) {
			/*fprintf(stderr, "%s: not found in sync db.  skipping.", local->name);*/
			continue;
		}

		/* compare versions and see if we need to upgrade */
		cmp = rpmvercmp(local->version, spkg->version);
		if(cmp > 0 && !spkg->force) {
			/* local version is newer */
			_alpm_log(PM_LOG_FLOW1, "%s-%s: local version is newer",
				local->name, local->version);
		} else if(cmp == 0) {
			/* versions are identical */
		} else if(pm_list_is_strin(i->data, handle->ignorepkg)) {
			/* package should be ignored (IgnorePkg) */
			_alpm_log(PM_LOG_FLOW1, "%s-%s: ignoring package upgrade (%s)",
				local->name, local->version, spkg->version);
		} else {
			sync = sync_new(PM_SYNC_TYPE_UPGRADE, local, spkg);
			if(sync == NULL) {
				pm_errno = PM_ERR_MEMORY;
				goto error;
			}
			_alpm_log(PM_LOG_DEBUG, "%s-%s elected for upgrade (%s => %s)",
				local->name, local->version, local->version, spkg->version);
			targets = pm_list_add(targets, sync);
		}
	}

	*data = targets;

	return(0);

error:
	FREELIST(targets);
	return(-1);
}

int sync_addtarget(pmdb_t *db, PMList *dbs_sync, pmtrans_t *trans, char *name)
{
	char targline[(PKG_NAME_LEN-1)+1+(DB_TREENAME_LEN-1)+1];
	char *targ;
	PMList *j;
	pmpkg_t *local;
	pmpkg_t *spkg = NULL;
	pmsyncpkg_t *sync;
	int cmp;

	ASSERT(db != NULL, RET_ERR(PM_ERR_DB_NULL, -1));
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(name != NULL, RET_ERR(PM_ERR_WRONG_ARGS, -1));

	if(trans->flags & PM_TRANS_FLAG_SYSUPG) {
		RET_ERR(PM_ERR_XXX, -1);
	}

	strncpy(targline, name, (PKG_NAME_LEN-1)+1+(DB_TREENAME_LEN-1)+1);
	targ = strchr(targline, '/');
	if(targ) {
		*targ = '\0';
		targ++;
		for(j = dbs_sync; j && !spkg; j = j->next) {
			pmdb_t *dbs = j->data;
			if(strcmp(dbs->treename, targline) == 0) {
				spkg = db_get_pkgfromcache(dbs, targ);
				if(spkg == NULL) {
					RET_ERR(PM_ERR_PKG_NOT_FOUND, -1);
				}
			}
		}
	} else {
		targ = targline;
		for(j = dbs_sync; j && !spkg; j = j->next) {
			pmdb_t *dbs = j->data;
			spkg = db_get_pkgfromcache(dbs, targ);
		}
	}
	if(spkg == NULL) {
		RET_ERR(PM_ERR_PKG_NOT_FOUND, -1);
	}

	local = db_get_pkgfromcache(db, name);
	if(local) {
		cmp = alpm_pkg_vercmp(local->version, spkg->version);
		if(cmp > 0) {
			/* local version is newer - get confirmation first */
			/* ORE
			if(!yesno(":: %s-%s: local version is newer.  Upgrade anyway? [Y/n] ", lpkgname, lpkgver)) {
			}*/
			_alpm_log(PM_LOG_WARNING, "%s-%s: local version is newer -- skipping");
			return(0);
		} else if(cmp == 0) {
			/* versions are identical */
			/* ORE
			if(!yesno(":: %s-%s: is up to date.  Upgrade anyway? [Y/n] ", lpkgname, lpkgver)) {
			}*/
			_alpm_log(PM_LOG_WARNING, "%s-%s: is up to date -- skipping");
			return(0);
		}
	}

	/* add the package to the transaction */
	if(!find_pkginsync(spkg->name, trans->packages)) {
		sync = sync_new(PM_SYNC_TYPE_UPGRADE, local, spkg);
		if(sync == NULL) {
			RET_ERR(PM_ERR_MEMORY, -1);
		}
		trans->packages = pm_list_add(trans->packages, sync);
	}

	return(0);
}

int sync_prepare(pmdb_t *db, pmtrans_t *trans, PMList **data)
{
	PMList *deps = NULL;
	PMList *list = NULL;
	PMList *trail = NULL;
	PMList *i;

	ASSERT(db != NULL, RET_ERR(PM_ERR_DB_NULL, -1));
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(data != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));

	*data = NULL;

	if(trans->packages == NULL) {
		return(0);
	}

	for(i = trans->packages; i; i = i->next) {
		pmsyncpkg_t *sync = i->data;
		list = pm_list_add(list, sync->spkg);
	}

	/* Resolve targets dependencies */
	if(!(trans->flags & PM_TRANS_FLAG_NODEPS)) {
		TRANS_CB(trans, PM_TRANS_EVT_RESOLVEDEPS_START, NULL, NULL);

		for(i = trans->packages; i; i = i->next) {
			pmsyncpkg_t *sync = i->data;
			list = pm_list_add(list, sync->spkg);
		}
		trail = pm_list_new();

		for(i = trans->packages; i; i = i->next) {
			pmsyncpkg_t *sync = i->data;
			pmpkg_t *spkg = sync->spkg;
			_alpm_log(PM_LOG_FLOW1, "resolving dependencies for package %s", spkg->name);
			if(resolvedeps(handle->db_local, handle->dbs_sync, spkg, list, trail) == -1) {
				/* pm_errno is set by resolvedeps */
				goto error;
			}
			/* ORE
			if called from makepkg, reason should be set to REASON_DEPEND
			spkg->reason = PM_PKG_REASON_EXPLICIT;*/
		}

		for(i = list; i; i = i->next) {
			pmpkg_t *spkg = i->data;
			if(!find_pkginsync(spkg->name, trans->packages)) {
				pmsyncpkg_t *sync = sync_new(PM_SYNC_TYPE_DEPEND, NULL, spkg);
				trans->packages = pm_list_add(trans->packages, sync);
			}
		}

		FREELISTPTR(list);
		FREELISTPTR(trail);

		TRANS_CB(trans, PM_TRANS_EVT_RESOLVEDEPS_DONE, NULL, NULL);
	}

	/* ORE
	check for inter-conflicts and whatnot */
	_alpm_log(PM_LOG_FLOW1, "looking for inter-conflicts");
	deps = checkdeps(db, PM_TRANS_TYPE_UPGRADE, list);
	if(deps) {
		int errorout = 0;
		for(i = deps; i; i = i->next) {
			pmdepmissing_t *miss = i->data;
			if(miss->type == PM_DEP_TYPE_DEPEND || miss->type == PM_DEP_TYPE_REQUIRED) {
				if(!errorout) {
					errorout = 1;
				}
				if((miss = (pmdepmissing_t *)malloc(sizeof(pmdepmissing_t))) == NULL) {
					FREELIST(deps);
					FREELIST(*data);
					RET_ERR(PM_ERR_MEMORY, -1);
				}
				*miss = *(pmdepmissing_t *)i->data;
				*data = pm_list_add(*data, miss);
			}
		}
		if(errorout) {
			FREELIST(deps);
			RET_ERR(PM_ERR_UNSATISFIED_DEPS, -1);
		}
		/* ORE
		then look for conflicts */
	}

	/* ORE
	any packages in rmtargs need to be removed from final.
	rather than ripping out nodes from final, we just copy over
	our "good" nodes to a new list and reassign. */

	/* ORE
	Check dependencies of packages in rmtargs and make sure
	we won't be breaking anything by removing them.
	If a broken dep is detected, make sure it's not from a
	package that's in our final (upgrade) list. */

	return(0);

error:
	FREELISTPTR(list);
	FREELISTPTR(trail);
	FREELIST(deps);
	return(-1);
}

int sync_commit(pmdb_t *db, pmtrans_t *trans)
{
	PMList *i, *j, *files = NULL;
	PMList *final = NULL;
	PMList *rmtargs = NULL;
	PMList *data;
	pmtrans_t *tr;

	/* remove any conflicting packages (WITHOUT dep checks) */
	/* ORE - alpm does not handle removal of conflicting pkgs for now */

	/* remove to-be-replaced packages */
	for(i = final; i; i = i->next) {
		pmsyncpkg_t *sync = i->data;
		for(j = sync->replaces; j; j = j->next) {
			pmpkg_t *pkg = j->data;
			rmtargs = pm_list_add(rmtargs, strdup(pkg->name));
		}
	}

	/* install targets */
	/* ORE - need for a flag specifying that deps have already been checked */
	tr = trans_new(PM_TRANS_TYPE_UPGRADE, 0);
	for(i = files; i; i = i->next) {
		trans_addtarget(tr, i->data);
	}
	trans_prepare(tr, &data);
	trans_commit(tr);
	trans_free(tr);

	/* propagate replaced packages' requiredby fields to their new owners */
	for(i = final; i; i = i->next) {
		/*syncpkg_t *sync = (syncpkg_t*)i->data;
		if(sync->replaces) {
			pkginfo_t *new = db_scan(db, sync->pkg->name, INFRQ_DEPENDS);
			for(j = sync->replaces; j; j = j->next) {
				pkginfo_t *old = (pkginfo_t*)j->data;
				// merge lists
				for(k = old->requiredby; k; k = k->next) {
					if(!is_in(k->data, new->requiredby)) {
						// replace old's name with new's name in the requiredby's dependency list
						PMList *m;
						pkginfo_t *depender = db_scan(db, k->data, INFRQ_DEPENDS);
						for(m = depender->depends; m; m = m->next) {
							if(!strcmp(m->data, old->name)) {
								FREE(m->data);
								m->data = strdup(new->name);
							}
						}
						db_write(db, depender, INFRQ_DEPENDS);

						// add the new requiredby
						new->requiredby = list_add(new->requiredby, strdup(k->data));
					}
				}
			}
			db_write(db, new, INFRQ_DEPENDS);
			FREEPKG(new);
		}*/
	}

	/* cache needs to be rebuilt */
	db_free_pkgcache(db);

	return(0);
}

/* vim: set ts=2 sw=2 noet: */

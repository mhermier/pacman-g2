/*
 *  sync.c
 * 
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
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
#include <time.h>
#ifdef CYGWIN
#include <limits.h> /* PATH_MAX */
#endif
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
#include "versioncmp.h"
#include "handle.h"
#include "util.h"
#include "alpm.h"
#include "md5.h"
#include "sha1.h"

extern pmhandle_t *handle;

pmsyncpkg_t *sync_new(int type, pmpkg_t *spkg, void *data)
{
	pmsyncpkg_t *sync;

	if((sync = (pmsyncpkg_t *)malloc(sizeof(pmsyncpkg_t))) == NULL) {
		return(NULL);
	}

	sync->type = type;
	sync->pkg = spkg;
	sync->data = data;
	
	return(sync);
}

void sync_free(pmsyncpkg_t *sync)
{
	if(sync == NULL) {
		return;
	}

	if(sync->type == PM_SYNC_TYPE_REPLACE) {
		FREELISTPKGS(sync->data);
	} else {
		FREEPKG(sync->data);
	}
	free(sync);
}

/* Test for existence of a package in a PMList* of pmsyncpkg_t*
 * If found, return a pointer to the respective pmsyncpkg_t*
 */
static pmsyncpkg_t* find_pkginsync(char *needle, PMList *haystack)
{
	PMList *i;
	pmsyncpkg_t *sync = NULL;
	int found = 0;

	for(i = haystack; i && !found; i = i->next) {
		sync = i->data;
		if(sync && !strcmp(sync->pkg->name, needle)) {
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
PMList *sync_load_dbarchive(char *archive)
{
	PMList *lp = NULL;
	DIR *dir = NULL;
	register struct archive *_archive;
	struct archive_entry *entry;
	
        if ((_archive = archive_read_new ()) == NULL) {
		pm_errno = PM_ERR_LIBARCHIVE_ERROR;
		goto error;
	}
	
        archive_read_support_compression_all(_archive);
        archive_read_support_format_all (_archive);

        if (archive_read_open_file (_archive, archive, 10240) != ARCHIVE_OK) {
		pm_errno = PM_ERR_NOT_A_FILE;
		goto error;
        }

	/* readdir tmp_dir */
	/* for each subdir, parse %s/desc and %s/depends */

	archive_read_finish(_archive);

	return(lp);

error:
	if(_archive) {
		archive_read_finish(_archive);
	}
	if(dir) {
		closedir(dir);
	}
	return(NULL);
}

int sync_sysupgrade(pmtrans_t *trans, pmdb_t *db_local, PMList *dbs_sync)
{
	PMList *i, *j, *k;

	/* check for "recommended" package replacements */
	for(i = dbs_sync; i; i = i->next) {
		for(j = db_get_pkgcache(i->data); j; j = j->next) {
			pmpkg_t *spkg = j->data;
			for(k = spkg->replaces; k; k = k->next) {
				PMList *m;
				_alpm_log(PM_LOG_DEBUG, "looking replacement %s for package %s", k->data, spkg->name);
				for(m = db_get_pkgcache(db_local); m; m = m->next) {
					pmpkg_t *lpkg = m->data;
					if(!strcmp(k->data, lpkg->name)) {
						if(pm_list_is_strin(lpkg->name, handle->ignorepkg)) {
							_alpm_log(PM_LOG_WARNING, "%s-%s: ignoring package upgrade (to be replaced by %s-%s)",
								lpkg->name, lpkg->version, spkg->name, spkg->version);
						} else {
							/* get confirmation for the replacement */
							int doreplace = 0;
							QUESTION(trans, PM_TRANS_CONV_REPLACE_PKG, lpkg, spkg, ((pmdb_t *)i->data)->treename, &doreplace);

							if(doreplace) {
								/* if confirmed, add this to the 'final' list, designating 'lpkg' as
								 * the package to replace.
								 */
								pmsyncpkg_t *sync;
								pmpkg_t *dummy = pkg_new(lpkg->name, NULL);
								if(dummy == NULL) {
									pm_errno = PM_ERR_MEMORY;
									goto error;
								}
								dummy->requiredby = _alpm_list_strdup(lpkg->requiredby);
								/* check if spkg->name is already in the packages list. */
								sync = find_pkginsync(spkg->name, trans->packages);
								if(sync) {
									/* found it -- just append to the replaces list */
									sync->data = pm_list_add(sync->data, dummy);
								} else {
									/* none found -- enter pkg into the final sync list */
									sync = sync_new(PM_SYNC_TYPE_REPLACE, spkg, NULL);
									if(sync == NULL) {
										FREEPKG(dummy);
										pm_errno = PM_ERR_MEMORY;
										goto error;
									}
									sync->data = pm_list_add(sync->data, dummy);
									trans->packages = pm_list_add(trans->packages, sync);
								}
								_alpm_log(PM_LOG_DEBUG, "%s-%s elected for upgrade (to be replaced by %s-%s)",
								          lpkg->name, lpkg->version, spkg->name, spkg->version);
							}
						}
						break;
					}
				}
			}
		}
	}

	/* match installed packages with the sync dbs and compare versions */
	for(i = db_get_pkgcache(db_local); i; i = i->next) {
		int cmp;
		int replace=0;
		pmpkg_t *local = i->data;
		pmpkg_t *spkg = NULL;
		pmsyncpkg_t *sync;

		for(j = dbs_sync; !spkg && j; j = j->next) {
			for(k = db_get_pkgcache(j->data); !spkg && k; k = k->next) {
				pmpkg_t *sp = k->data;
				if(!strcmp(local->name, sp->name)) {
					spkg = sp;
				}
			}
		}
		if(spkg == NULL) {
			/*_alpm_log(PM_LOG_ERROR, "%s: not found in sync db -- skipping.", local->name);*/
			continue;
		}
	
		/* we don't care about a to-be-replaced package's newer version */
		for(j = trans->packages; j && !replace; j=j->next) {
			sync = j->data;
			if(sync->type == PM_SYNC_TYPE_REPLACE) {
				for(k=sync->data; k && !replace; k=k->next) {
					if(!strcmp(((pmpkg_t*)k->data)->name, spkg->name)) {
						replace=1;
					}
				}
			}
		}
		if(replace) {
			_alpm_log(PM_LOG_DEBUG, "%s is already elected for removal -- skipping",
								local->name);
			continue;
		}

		/* compare versions and see if we need to upgrade */
		cmp = versioncmp(local->version, spkg->version);
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
		} else if(sync_istoonew(spkg)) {
			/* package too new (UpgradeDelay) */
			_alpm_log(PM_LOG_FLOW1, "%s-%s: delaying upgrade of package (%s)\n",
					local->name, local->version, spkg->version);
		} else {
			pmpkg_t *dummy = pkg_new(local->name, local->version);
			sync = sync_new(PM_SYNC_TYPE_UPGRADE, spkg, dummy);
			if(sync == NULL) {
				FREEPKG(dummy);
				pm_errno = PM_ERR_MEMORY;
				goto error;
			}
			_alpm_log(PM_LOG_DEBUG, "%s-%s elected for upgrade (%s => %s)",
				local->name, local->version, local->version, spkg->version);
			trans->packages = pm_list_add(trans->packages, sync);
		}
	}

	return(0);

error:
	return(-1);
}

int sync_istoonew(pmpkg_t *pkg)
{
	time_t t;
	if (!handle->upgradedelay)
		return 0;
	time(&t);
	return((pkg->date + handle->upgradedelay) > t);
}

int sync_addtarget(pmtrans_t *trans, pmdb_t *db_local, PMList *dbs_sync, char *name)
{
	char targline[PKG_FULLNAME_LEN];
	char *targ;
	PMList *j;
	pmpkg_t *local;
	pmpkg_t *spkg = NULL;
	pmsyncpkg_t *sync;
	int cmp;

	ASSERT(db_local != NULL, RET_ERR(PM_ERR_DB_NULL, -1));
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(name != NULL, RET_ERR(PM_ERR_WRONG_ARGS, -1));

	STRNCPY(targline, name, PKG_FULLNAME_LEN);
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

	local = db_get_pkgfromcache(db_local, name);
	if(local) {
		cmp = versioncmp(local->version, spkg->version);
		if(cmp > 0) {
			/* local version is newer -- get confirmation before adding */
			int resp = 0;
			QUESTION(trans, PM_TRANS_CONV_LOCAL_NEWER, local, NULL, NULL, &resp);
			if(!resp) {
				_alpm_log(PM_LOG_WARNING, "%s-%s: local version is newer -- skipping", local->name, local->version);
				return(0);
			}
		} else if(cmp == 0) {
			/* versions are identical -- get confirmation before adding */
			int resp = 0;
			QUESTION(trans, PM_TRANS_CONV_LOCAL_UPTODATE, local, NULL, NULL, &resp);
			if(!resp) {
				_alpm_log(PM_LOG_WARNING, "%s-%s is up to date -- skipping", local->name, local->version);
				return(0);
			}
		}
	}

	/* add the package to the transaction */
	if(!find_pkginsync(spkg->name, trans->packages)) {
		pmpkg_t *dummy = NULL;
		if(local) {
			dummy = pkg_new(local->name, local->version);
			if(dummy == NULL) {
				RET_ERR(PM_ERR_MEMORY, -1);
			}
		}
		sync = sync_new(PM_SYNC_TYPE_UPGRADE, spkg, dummy);
		if(sync == NULL) {
			FREEPKG(dummy);
			RET_ERR(PM_ERR_MEMORY, -1);
		}
		trans->packages = pm_list_add(trans->packages, sync);
	}

	return(0);
}

/* Helper function for _alpm_list_remove
 */
static int ptr_cmp(const void *s1, const void *s2)
{
	return((s1 == s2));
}

int sync_prepare(pmtrans_t *trans, pmdb_t *db_local, PMList *dbs_sync, PMList **data)
{
	PMList *deps = NULL;
	PMList *list = NULL; /* list allowing checkdeps usage with data from trans->packages */
	PMList *trail = NULL; /* breadcrum list to avoid running into circles */
	PMList *asked = NULL; 
	PMList *i, *j, *k, *l;

	ASSERT(db_local != NULL, RET_ERR(PM_ERR_DB_NULL, -1));
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));

	if(data) {
		*data = NULL;
	}

	if(!(trans->flags & PM_TRANS_FLAG_NODEPS)) {
		for(i = trans->packages; i; i = i->next) {
			pmsyncpkg_t *sync = i->data;
			list = pm_list_add(list, sync->pkg);
		}
		trail = _alpm_list_new();

		/* Resolve targets dependencies */
		EVENT(trans, PM_TRANS_EVT_RESOLVEDEPS_START, NULL, NULL);
		_alpm_log(PM_LOG_FLOW1, "resolving targets dependencies");
		for(i = trans->packages; i; i = i->next) {
			pmpkg_t *spkg = ((pmsyncpkg_t *)i->data)->pkg;
			_alpm_log(PM_LOG_DEBUG, "resolving dependencies for package %s", spkg->name);
			if(resolvedeps(db_local, dbs_sync, spkg, list, trail, trans) == -1) {
				/* pm_errno is set by resolvedeps */
				goto error;
			}
		}
		for(i = list; i; i = i->next) {
			/* add the dependencies found by resolvedeps to the transaction set */
			pmpkg_t *spkg = i->data;
			if(!find_pkginsync(spkg->name, trans->packages)) {
				pmsyncpkg_t *sync = sync_new(PM_SYNC_TYPE_DEPEND, spkg, NULL);
				/* ORE - the trans->packages list should be sorted to stay compatible with
				 * pacman 2.x */
				trans->packages = pm_list_add(trans->packages, sync);
				_alpm_log(PM_LOG_FLOW2, "adding package %s-%s to the transaction targets",
						spkg->name, spkg->version);
			}
		}

		/* remove original targets from final if requested */
		if((trans->flags & PM_TRANS_FLAG_DEPENDSONLY)) {
			k = NULL;
			for(i = trans->packages; i; i = i->next)
			{
				pmsyncpkg_t *s = (pmsyncpkg_t*)i->data;
				int keepit = 1;
				for(j = list; j; j = j->next)
				{
					if(!strcmp(j->data, s->pkg->name))
					{
						FREE(i->data);
						keepit = 0;
					}
					if(keepit)
						k = pm_list_add(k, s);
					i->data = NULL;
				}
			}
			FREELIST(trans->packages);
			trans->packages = k;
		}

		/* re-order w.r.t. dependencies */
		k = l = NULL;
		for(i=trans->packages; i; i=i->next) {
			pmsyncpkg_t *s = (pmsyncpkg_t*)i->data;
			k = pm_list_add(k, s->pkg);
		}
		k = sortbydeps(k, PM_TRANS_TYPE_ADD);
		for(i=k; i; i=i->next) {
			for(j=trans->packages; j; j=j->next) {
				pmsyncpkg_t *s = (pmsyncpkg_t*)j->data;
				if(s->pkg==i->data) {
					l = pm_list_add(l, s);
				}
			}
		}
		FREELISTPTR(trans->packages);
		trans->packages = l;

		EVENT(trans, PM_TRANS_EVT_RESOLVEDEPS_DONE, NULL, NULL);

		/* check for inter-conflicts and whatnot */
		EVENT(trans, PM_TRANS_EVT_INTERCONFLICTS_START, NULL, NULL);
		deps = checkdeps(db_local, PM_TRANS_TYPE_UPGRADE, list);
		if(deps) {
			int errorout = 0;
			_alpm_log(PM_LOG_FLOW1, "looking for unresolvable dependencies");
			for(i = deps; i; i = i->next) {
				pmdepmissing_t *miss = i->data;
				if(miss->type == PM_DEP_TYPE_DEPEND || miss->type == PM_DEP_TYPE_REQUIRED) {
					if(!errorout) {
						errorout = 1;
					}
					if(data) {
						if((miss = (pmdepmissing_t *)malloc(sizeof(pmdepmissing_t))) == NULL) {
							FREELIST(*data);
							pm_errno = PM_ERR_MEMORY;
							goto error;
						}
						*miss = *(pmdepmissing_t *)i->data;
						*data = pm_list_add(*data, miss);
					}
				}
			}
			if(errorout) {
				pm_errno = PM_ERR_UNSATISFIED_DEPS;
				goto error;
			}

			/* no unresolvable deps, so look for conflicts */
			_alpm_log(PM_LOG_FLOW1, "looking for conflicts");
			for(i = deps; i && !errorout; i = i->next) {
				pmdepmissing_t *miss = i->data;
				PMList *k;
				int found = 0;

				if(miss->type != PM_DEP_TYPE_CONFLICT) {
					continue;
				}

				_alpm_log(PM_LOG_DEBUG, "package %s is conflicting with %s",
				          miss->target, miss->depend.name);

				/* check if the conflicting package is one that's about to be removed/replaced.
				 * if so, then just ignore it
				 */
				for(j = trans->packages; j && !found; j = j->next) {
					pmsyncpkg_t *sync = j->data;
					if(sync->type == PM_SYNC_TYPE_REPLACE) {
						for(k = sync->data; k && !found; k = k->next) {
							pmpkg_t *p = k->data;
							if(!strcmp(p->name, miss->depend.name)) {
								_alpm_log(PM_LOG_DEBUG, "%s is already elected for removal -- skipping",
								          miss->depend.name);
								found = 1;
							}
						}
					}
				}

				/* if we didn't find it in any sync->replaces lists, then it's a conflict */
				if(!found) {
					int solved = 0;
					pmsyncpkg_t *sync = find_pkginsync(miss->target, trans->packages);
					for(j = sync->pkg->provides; j && j->data && !solved; j = j->next) {
						if(!strcmp(j->data, miss->depend.name)) {
							/* this package also "provides" the package it's conflicting with,
							 * so just treat it like a "replaces" item so the REQUIREDBY
							 * fields are inherited properly.
							 */
							if(db_get_pkgfromcache(db_local, miss->depend.name) == NULL) {
								char *rmpkg = NULL;
								/* hmmm, depend.name isn't installed, so it must be conflicting
								 * with another package in our final list.  For example:
								 *
								 *     pacman -S blackbox xfree86
								 *
								 * If no x-servers are installed and blackbox pulls in xorg, then
								 * xorg and xfree86 will conflict with each other.  In this case,
								 * we should follow the user's preference and rip xorg out of final,
								 * opting for xfree86 instead.
								 */

								/* figure out which one was requested in targets.  If they both were,
								 * then it's still an unresolvable conflict. */
								if(pm_list_is_strin(miss->depend.name, trans->targets)
								   && !pm_list_is_strin(miss->target, trans->targets)) {
									/* remove miss->target */
									rmpkg = strdup(miss->target);
								} else if(pm_list_is_strin(miss->target, trans->targets)
								          && !pm_list_is_strin(miss->depend.name, trans->targets)) {
									/* remove miss->depend.name */
									rmpkg = strdup(miss->depend.name);
								} else {
									/* something's not right, bail out with a conflict error */
								}
								if(rmpkg) {
									for(k= trans->packages; k; k=k->next) {
										pmsyncpkg_t *sync = k->data;
										if(!strcmp(sync->pkg->name, rmpkg)) {
											pmsyncpkg_t *spkg;
											trans->packages = _alpm_list_remove(trans->packages, sync, ptr_cmp, (void **)&spkg);
											FREESYNC(spkg);
											_alpm_log(PM_LOG_DEBUG, "removing %s from target list", rmpkg);
											/* ORE - shouldn't "solved" be set to 1 here */
										}
									}
									solved = 1;
									FREE(rmpkg);
								}
							}
						}
					}
					if(!solved) {
						/* It's a conflict -- see if they want to remove it
						 */

						_alpm_log(PM_LOG_DEBUG, "resolving package %s conflict", miss->target);

						if(db_get_pkgfromcache(db_local, miss->depend.name)) {
							int doremove = 0;
							if(!pm_list_is_strin(miss->depend.name, asked)) {
								QUESTION(trans, PM_TRANS_CONV_CONFLICT_PKG, miss->target, miss->depend.name, NULL, &doremove);
								asked = pm_list_add(asked, strdup(miss->depend.name));
								if(doremove) {
									/* remove miss->depend.name */
									k=_alpm_list_new();
									pmpkg_t *q = pkg_new(miss->depend.name, NULL);
									k = pm_list_add(k, q);
									for(l = trans->packages; l; l=l->next) {
										pmsyncpkg_t *s = l->data;
										if(!strcmp(s->pkg->name, miss->target)) {
											s->data = k;
											s->type = PM_SYNC_TYPE_REPLACE;
										}
									}
								} else {
									/* abort */
									_alpm_log(PM_LOG_ERROR, "package conflicts detected");
									errorout=1;
									if(data) {
										if((miss = (pmdepmissing_t *)malloc(sizeof(pmdepmissing_t))) == NULL) {
											FREELIST(*data);
											pm_errno = PM_ERR_MEMORY;
											goto error;
										}
										*miss = *(pmdepmissing_t *)i->data;
										*data = pm_list_add(*data, miss);
									}
								}
							}
						} else {
							_alpm_log(PM_LOG_ERROR, "%s conflicts with %s", miss->target, miss->depend.name);
							errorout = 1;
							if(data) {
								if((miss = (pmdepmissing_t *)malloc(sizeof(pmdepmissing_t))) == NULL) {
									FREELIST(*data);
									pm_errno = PM_ERR_MEMORY;
									goto error;
								}
								*miss = *(pmdepmissing_t *)i->data;
								*data = pm_list_add(*data, miss);
							}
						}
					}
				}
			}
			if(errorout) {
				pm_errno = PM_ERR_CONFLICTING_DEPS;
				goto error;
			}
			FREELIST(deps);
		}
		EVENT(trans, PM_TRANS_EVT_INTERCONFLICTS_DONE, NULL, NULL);

		FREELISTPTR(list);
		FREELISTPTR(trail);
		FREELIST(asked);

		/* XXX: this fails for cases where a requested package wants
		 *      a dependency that conflicts with an older version of
		 *      the package.  It will be removed from final, and the user
		 *      has to re-request it to get it installed properly.
		 *
		 *      Not gonna happen very often, but should be dealt with...
		 */

		/* Check dependencies of packages in rmtargs and make sure
		 * we won't be breaking anything by removing them.
		 * If a broken dep is detected, make sure it's not from a
		 * package that's in our final (upgrade) list.
		 */
		/*EVENT(trans, PM_TRANS_EVT_CHECKDEPS_DONE, NULL, NULL);*/
		for(i = trans->packages; i; i = i->next) {
			pmsyncpkg_t *sync = i->data;
			if(sync->type == PM_SYNC_TYPE_REPLACE) {
				for(j = sync->data; j; j = j->next) {
					list = pm_list_add(list, j->data);
				}
			}
		}
		if(list) {
			_alpm_log(PM_LOG_FLOW1, "checking dependencies of packages designated for removal");
			deps = checkdeps(db_local, PM_TRANS_TYPE_REMOVE, list);
			if(deps) {
				if(data) {
					*data = deps;
				}
				pm_errno = PM_ERR_UNSATISFIED_DEPS;
				goto error;
			}
			FREELISTPTR(list);
		}
		/*EVENT(trans, PM_TRANS_EVT_CHECKDEPS_DONE, NULL, NULL);*/
	}

	return(0);

error:
	FREELISTPTR(list);
	FREELISTPTR(trail);
	FREELIST(asked);
	return(-1);
}

int sync_commit(pmtrans_t *trans, pmdb_t *db_local, PMList **data)
{
	PMList *i;
	pmtrans_t *tr = NULL;
	int replaces = 0, retval = 0;

	ASSERT(db_local != NULL, RET_ERR(PM_ERR_DB_NULL, -1));
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));

	/* Check integrity of files */
	EVENT(trans, PM_TRANS_EVT_INTEGRITY_START, NULL, NULL);

	for(i = trans->packages; i; i = i->next) {
		pmsyncpkg_t *sync = i->data;
		pmpkg_t *spkg = sync->pkg;
		char str[PATH_MAX], pkgname[PATH_MAX];
		char *md5sum1, *md5sum2, *sha1sum1, *sha1sum2;
		char *ptr=NULL;

		snprintf(pkgname, PATH_MAX, "%s-%s-%s" PM_EXT_PKG,
			spkg->name, spkg->version, spkg->arch);
		md5sum1 = spkg->md5sum;
		sha1sum1 = spkg->sha1sum;

		if((md5sum1 == NULL) && (sha1sum1 == NULL)) {
			MALLOC(ptr, 512);
			snprintf(ptr, 512, "can't get md5 or sha1 checksum for package %s\n", pkgname);
			*data = pm_list_add(*data, ptr);
			retval = 1;
			continue;
		}
		snprintf(str, PATH_MAX, "%s/%s/%s", handle->root, handle->cachedir, pkgname);
		md5sum2 = MDFile(str);
		sha1sum2 = SHAFile(str);
		if(md5sum2 == NULL && sha1sum2 == NULL) {
			MALLOC(ptr, 512);
			snprintf(ptr, 512, "can't get md5 or sha1 checksum for package %s\n", pkgname);
			*data = pm_list_add(*data, ptr);
			retval = 1;
			continue;
		}
		if((strcmp(md5sum1, md5sum2) != 0) && (strcmp(sha1sum1, sha1sum2) != 0)) {
			MALLOC(ptr, 512);
			snprintf(ptr, 512, "archive %s is corrupted (bad MD5 or SHA1 checksum)\n", pkgname);
			*data = pm_list_add(*data, ptr);
			retval = 1;
		}
		FREE(md5sum2);
		FREE(sha1sum2);
	}
	if(retval) {
		pm_errno = PM_ERR_PKG_CORRUPTED;
		goto error;
	}
	EVENT(trans, PM_TRANS_EVT_INTEGRITY_DONE, NULL, NULL);
	if(trans->flags & PM_TRANS_FLAG_DOWNLOADONLY) {
		return(0);
	}

	/* remove conflicting and to-be-replaced packages */
	tr = trans_new();
	if(tr == NULL) {
		_alpm_log(PM_LOG_ERROR, "could not create removal transaction");
		pm_errno = PM_ERR_MEMORY;
		goto error;
	}

	if(trans_init(tr, PM_TRANS_TYPE_REMOVE, PM_TRANS_FLAG_NODEPS, NULL, NULL, NULL) == -1) {
		_alpm_log(PM_LOG_ERROR, "could not initialize the removal transaction");
		goto error;
	}

	for(i = trans->packages; i; i = i->next) {
		pmsyncpkg_t *sync = i->data;
		if(sync->type == PM_SYNC_TYPE_REPLACE) {
			PMList *j;
			for(j = sync->data; j; j = j->next) {
				pmpkg_t *pkg = j->data;
				if(!pkg_isin(pkg, tr->packages)) {
					if(trans_addtarget(tr, pkg->name) == -1) {
						goto error;
					}
					replaces++;
				}
			}
		}
	}
	if(replaces) {
		_alpm_log(PM_LOG_FLOW1, "removing conflicting and to-be-replaced packages");
		if(trans_prepare(tr, data) == -1) {
			_alpm_log(PM_LOG_ERROR, "could not prepare removal transaction");
			pm_errno = PM_ERR_XXX;
			goto error;
		}
		/* we want the frontend to be aware of commit details */
		tr->cb_event = trans->cb_event;
		if(trans_commit(tr, NULL) == -1) {
			_alpm_log(PM_LOG_ERROR, "could not commit removal transaction");
			pm_errno = PM_ERR_XXX;
			goto error;
		}
	}
	FREETRANS(tr);

	/* install targets */
	_alpm_log(PM_LOG_FLOW1, "installing packages");
	tr = trans_new();
	if(tr == NULL) {
		_alpm_log(PM_LOG_ERROR, "could not create transaction");
		pm_errno = PM_ERR_MEMORY;
		goto error;
	}
	if(trans_init(tr, PM_TRANS_TYPE_UPGRADE, trans->flags | PM_TRANS_FLAG_NODEPS, NULL, NULL, NULL) == -1) {
		_alpm_log(PM_LOG_ERROR, "could not initialize transaction");
		goto error;
	}
	for(i = trans->packages; i; i = i->next) {
		pmsyncpkg_t *sync = i->data;
		pmpkg_t *spkg = sync->pkg;
		char str[PATH_MAX];
		snprintf(str, PATH_MAX, "%s%s/%s-%s-%s" PM_EXT_PKG, handle->root, handle->cachedir, spkg->name, spkg->version, spkg->arch);
		if(trans_addtarget(tr, str) == -1) {
			goto error;
		}
		/* using _alpm_list_last() is ok because addtarget() adds the new target at the
		 * end of the tr->packages list */
		spkg = _alpm_list_last(tr->packages)->data;
		if(sync->type == PM_SYNC_TYPE_DEPEND) {
			spkg->reason = PM_PKG_REASON_DEPEND;
		}
	}
	if(trans_prepare(tr, data) == -1) {
		_alpm_log(PM_LOG_ERROR, "could not prepare transaction");
		/* pm_errno is set by trans_prepare */
		goto error;
	}
	/* we want the frontend to be aware of commit details */
	tr->cb_event = trans->cb_event;
	tr->cb_progress = trans->cb_progress;
	if(trans_commit(tr, NULL) == -1) {
		_alpm_log(PM_LOG_ERROR, "could not commit transaction");
		goto error;
	}
	FREETRANS(tr);

	/* propagate replaced packages' requiredby fields to their new owners */
	if(replaces) {
		_alpm_log(PM_LOG_FLOW1, "updating database for replaced packages dependencies");
		for(i = trans->packages; i; i = i->next) {
			pmsyncpkg_t *sync = i->data;
			if(sync->type == PM_SYNC_TYPE_REPLACE) {
				PMList *j;
				pmpkg_t *new = db_get_pkgfromcache(db_local, sync->pkg->name);
				for(j = sync->data; j; j = j->next) {
					PMList *k;
					pmpkg_t *old = j->data;
					/* merge lists */
					for(k = old->requiredby; k; k = k->next) {
						if(!pm_list_is_strin(k->data, new->requiredby)) {
							/* replace old's name with new's name in the requiredby's dependency list */
							PMList *m;
							pmpkg_t *depender = db_get_pkgfromcache(db_local, k->data);
							if(depender == NULL) {
								/* If the depending package no longer exists in the local db,
								 * then it must have ALSO conflicted with sync->pkg.  If
								 * that's the case, then we don't have anything to propagate
								 * here. */
								continue;
							}
							for(m = depender->depends; m; m = m->next) {
								if(!strcmp(m->data, old->name)) {
									FREE(m->data);
									m->data = strdup(new->name);
								}
							}
							if(db_write(db_local, depender, INFRQ_DEPENDS) == -1) {
								_alpm_log(PM_LOG_ERROR, "could not update 'requiredby' database entry %s/%s-%s", db_local->treename, new->name, new->version);
							}
							/* add the new requiredby */
							new->requiredby = pm_list_add(new->requiredby, strdup(k->data));
						}
					}
				}
				if(db_write(db_local, new, INFRQ_DEPENDS) == -1) {
					_alpm_log(PM_LOG_ERROR, "could not update new database entry %s/%s-%s", db_local->treename, new->name, new->version);
				}
			}
		}
	}

	return(0);

error:
	FREETRANS(tr);
	return(-1);
}

/* vim: set ts=2 sw=2 noet: */

/*
 *  deps.c
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/* pacman */
#include "util.h"
#include "log.h"
#include "list.h"
#include "package.h"
#include "db.h"
#include "cache.h"
#include "provide.h"
#include "deps.h"
#include "rpmvercmp.h"

/* Re-order a list of target packages with respect to their dependencies.
 *
 * Example (PM_TRANS_TYPE_ADD):
 *   A depends on C
 *   B depends on A
 *   Target order is A,B,C,D
 *
 *   Should be re-ordered to C,A,B,D
 * 
 * mode should be either PM_TRANS_TYPE_ADD or PM_TRANS_TYPE_REMOVE.  This
 * affects the dependency order sortbydeps() will use.
 *
 * This function returns the new PMList* target list.
 *
 */ 
PMList *sortbydeps(PMList *targets, int mode)
{
	PMList *newtargs = NULL;
	PMList *i, *j, *k;
	int change = 1;
	int numscans = 0;
	int numtargs = 0;
	int clean = 0;

	if(targets == NULL) {
		return(NULL);
	}

	/* count the number of targets */
	numtargs = pm_list_count(targets);

	while(change) {
		change = 0;
		if(numscans > numtargs) {
			_alpm_log(PM_LOG_FLOW2, "warning: possible dependency cycle detected\n");
			change = 0;
			continue;
		}
		newtargs = NULL;
		numscans++;
		/* run thru targets, moving up packages as necessary */
		for(i = targets; i; i = i->next) {
			pmpkg_t *p = (pmpkg_t*)i->data;
			for(j = p->depends; j; j = j->next) {
				pmdepend_t dep;
				int found = 0;
				pmpkg_t *q = NULL;

				splitdep(j->data, &dep);
				/* look for dep.name -- if it's farther down in the list, then
				 * move it up above p
				 */
				for(k = i->next; k && !found; k = k->next) {
					q = (pmpkg_t*)k->data;
					if(!strcmp(dep.name, q->name)) {
						found = 1;
					}
				}
				if(found) {
					if(!pkg_isin(q, newtargs)) {
						change = 1;
						newtargs = pm_list_add(newtargs, q);
					}
				}
			}
			if(!pkg_isin(p, newtargs)) {
				newtargs = pm_list_add(newtargs, p);
			}
		}
		if(clean && change) {
			/* free up targets -- it's local now */
			for(i = targets; i; i = i->next) {
				i->data = NULL;
			}
			FREELIST(targets);
		}
		targets = newtargs;
		clean = 1;
	}
	if(mode == PM_TRANS_TYPE_REMOVE) {
		/* we're removing packages, so reverse the order */
		newtargs = _alpm_list_reverse(targets);
		/* free the old one */
		for(i = targets; i; i = i->next) {
			i->data = NULL;
		}
		FREELIST(targets);
		targets = newtargs;
	}

	return(targets);
}

/* Returns a PMList* of missing_t pointers.
 *
 * conflicts are always name only, but dependencies can include versions
 * with depmod operators.
 *
 */
PMList *checkdeps(pmdb_t *db, unsigned short op, PMList *packages)
{
	pmpkg_t *info = NULL;
	pmdepend_t depend;
	PMList *i, *j, *k;
	int cmp;
	int found = 0;
	PMList *baddeps = NULL;
	pmdepmissing_t *miss = NULL;

	if(db == NULL) {
		return(NULL);
	}

	if(op == PM_TRANS_TYPE_UPGRADE) {
		/* PM_TRANS_TYPE_UPGRADE handles the backwards dependencies, ie, the packages
		 * listed in the requiredby field.
		 */
		for(i = packages; i; i = i->next) {
			pmpkg_t *tp, *oldpkg;
			if(i->data == NULL) {
				continue;
			}
			tp = (pmpkg_t *)i->data;

			if((oldpkg = db_scan(db, tp->name, INFRQ_DESC | INFRQ_DEPENDS)) == NULL) {
				continue;
			}
			for(j = oldpkg->requiredby; j; j = j->next) {
				char *ver;
				pmpkg_t *p;
				found = 0;
				if((p = db_scan(db, j->data, INFRQ_DESC | INFRQ_DEPENDS)) == NULL) {
					/* hmmm... package isn't installed.. */
					continue;
				}
				if(pkg_isin(p, packages)) {
					/* this package is also in the upgrade list, so don't worry about it */
					FREEPKG(p);
					continue;
				}
				for(k = p->depends; k && !found; k = k->next) {
					/* find the dependency info in p->depends */
					splitdep(k->data, &depend);
					if(!strcmp(depend.name, oldpkg->name)) {
						found = 1;
					}
				}
				if(found == 0) {
					PMList *lp;
					/* look for packages that list depend.name as a "provide" */
					PMList *provides = _alpm_db_whatprovides(db, depend.name);
					if(provides == NULL) {
						/* not found */
						FREEPKG(p);
						continue;
					}
					/* we found an installed package that provides depend.name */
					for(lp = provides; lp; lp = lp->next) {
						lp->data = NULL;
					}
					pm_list_free(provides);
				}
				found = 0;
				if(depend.mod == PM_DEP_ANY) {
					found = 1;
				} else {
					/* note that we use the version from the NEW package in the check */
					ver = strdup(tp->version);
					if(!index(depend.version,'-')) {
						char *ptr;
						for(ptr = ver; *ptr != '-'; ptr++);
						*ptr = '\0';
					}
					cmp = rpmvercmp(ver, depend.version);
					switch(depend.mod) {
						case PM_DEP_EQ: found = (cmp == 0); break;
						case PM_DEP_GE: found = (cmp >= 0); break;
						case PM_DEP_LE: found = (cmp <= 0); break;
					}
					FREE(ver);
				}
				if(!found) {
					MALLOC(miss, sizeof(pmdepmissing_t));
					miss->type = PM_DEP_REQUIRED;
					miss->depend.mod = depend.mod;
					strncpy(miss->target, p->name, 256);
					strncpy(miss->depend.name, depend.name, 256);
					strncpy(miss->depend.version, depend.version, 64);
					if(!pm_list_is_ptrin(baddeps, miss)) {
						baddeps = pm_list_add(baddeps, miss);
					}
				}
				FREEPKG(p);
			}
			FREEPKG(oldpkg);
		}
	}
	if(op == PM_TRANS_TYPE_ADD || op == PM_TRANS_TYPE_UPGRADE) {
		for(i = packages; i; i = i->next) {
			pmpkg_t *tp = i->data;
			if(tp == NULL) {
				continue;
			}

			/* CONFLICTS */
			for(j = tp->conflicts; j; j = j->next) {
				/* check targets against database */
				for(k = db_get_pkgcache(db); k; k = k->next) {
					pmpkg_t *dp = (pmpkg_t *)k->data;
					if(!strcmp(j->data, dp->name)) {
						MALLOC(miss, sizeof(pmdepmissing_t));
						miss->type = PM_DEP_CONFLICT;
						miss->depend.mod = PM_DEP_ANY;
						miss->depend.version[0] = '\0';
						strncpy(miss->target, tp->name, 256);
						strncpy(miss->depend.name, dp->name, 256);
						if(!pm_list_is_ptrin(baddeps, miss)) {
							baddeps = pm_list_add(baddeps, miss);
						}
					}
				}
				/* check targets against targets */
				for(k = packages; k; k = k->next) {
					pmpkg_t *a = (pmpkg_t *)k->data;
					if(!strcmp(a->name, (char *)j->data)) {
						MALLOC(miss, sizeof(pmdepmissing_t));
						miss->type = PM_DEP_CONFLICT;
						miss->depend.mod = PM_DEP_ANY;
						miss->depend.version[0] = '\0';
						strncpy(miss->target, tp->name, 256);
						strncpy(miss->depend.name, a->name, 256);
						if(!pm_list_is_ptrin(baddeps, miss)) {
							baddeps = pm_list_add(baddeps, miss);
						}
					}
				}
			}
			/* check database against targets */
			for(k = db_get_pkgcache(db); k; k = k->next) {
				info = k->data;
				for(j = info->conflicts; j; j = j->next) {
					if(!strcmp((char *)j->data, tp->name)) {
						MALLOC(miss, sizeof(pmdepmissing_t));
						miss->type = PM_DEP_CONFLICT;
						miss->depend.mod = PM_DEP_ANY;
						miss->depend.version[0] = '\0';
						strncpy(miss->target, tp->name, 256);
						strncpy(miss->depend.name, info->name, 256);
						if(!pm_list_is_ptrin(baddeps, miss)) {
							baddeps = pm_list_add(baddeps, miss);
						}
					}
				}
			}

			/* PROVIDES -- check to see if another package already provides what
			 *             we offer
 			 */
			/* XXX: disabled -- we allow multiple packages to provide the same thing.
			 *      list packages in conflicts if they really do conflict.
			for(j = tp->provides; j; j = j->next) {
				PMList *provs = whatprovides(db, j->data);
				for(k = provs; k; k = k->next) {
					if(!strcmp(tp->name, k->data->name)) {
						// this is the same package -- skip it
						continue;
					}
					// we treat this just like a conflict
					MALLOC(miss, sizeof(pmdepmissing_t));
					miss->type = CONFLICT;
					miss->depend.mod = PM_DEP_ANY;
					miss->depend.version[0] = '\0';
					strncpy(miss->target, tp->name, 256);
					strncpy(miss->depend.name, k->data, 256);
					if(!pm_list_is_in(baddeps, miss)) {
						baddeps = pm_list_add(baddeps, miss);
					}
					k->data = NULL;
				}
				pm_list_free(provs);
			}*/

			/* DEPENDENCIES -- look for unsatisfied dependencies */
			for(j = tp->depends; j; j = j->next) {
				/* split into name/version pairs */
				splitdep((char *)j->data, &depend);
				found = 0;
				/* check database for literal packages */
				for(k = db_get_pkgcache(db); k && !found; k = k->next) {
					pmpkg_t *p = (pmpkg_t *)k->data;
					if(!strcmp(p->name, depend.name)) {
						if(depend.mod == PM_DEP_ANY) {
							/* accept any version */
							found = 1;
						} else {
							char *ver = strdup(p->version);
							/* check for a release in depend.version.  if it's
							 * missing remove it from p->version as well.
							 */
							if(!index(depend.version,'-')) {
								char *ptr;
								for(ptr = ver; *ptr != '-'; ptr++);
								*ptr = '\0';
							}
							cmp = rpmvercmp(ver, depend.version);
							switch(depend.mod) {
								case PM_DEP_EQ: found = (cmp == 0); break;
								case PM_DEP_GE: found = (cmp >= 0); break;
								case PM_DEP_LE: found = (cmp <= 0); break;
							}
							FREE(ver);
						}
					}
				}
				/* check other targets */
				for(k = packages; k && !found; k = k->next) {
					pmpkg_t *p = (pmpkg_t *)k->data;
					/* see if the package names match OR if p provides depend.name */
					if(!strcmp(p->name, depend.name) || pm_list_is_strin(depend.name, p->provides)) {
						if(depend.mod == PM_DEP_ANY) {
							/* accept any version */
							found = 1;
						} else {
							char *ver = strdup(p->version);
							/* check for a release in depend.version.  if it's
							 * missing remove it from p->version as well.
							 */
							if(!index(depend.version,'-')) {
								char *ptr;
								for(ptr = ver; *ptr != '-'; ptr++);
								*ptr = '\0';
							}
							cmp = rpmvercmp(ver, depend.version);
							switch(depend.mod) {
								case PM_DEP_EQ: found = (cmp == 0); break;
								case PM_DEP_GE: found = (cmp >= 0); break;
								case PM_DEP_LE: found = (cmp <= 0); break;
							}
							FREE(ver);
						}
					}
				}
				/* check database for provides matches */
				if(!found){
					PMList *lp;
					k = _alpm_db_whatprovides(db, depend.name);
					if(k) {
						/* grab the first one (there should only really be one, anyway) */
						pmpkg_t *p = db_scan(db, ((pmpkg_t *)k->data)->name, INFRQ_DESC);
						if(p == NULL) {
							/* wtf */
							fprintf(stderr, "data error: %s supposedly provides %s, but it was not found in db\n",
								((pmpkg_t *)k->data)->name, depend.name);
							for(lp = k; lp; lp = lp->next) {
								lp->data = NULL;
							}
							pm_list_free(k);
							continue;
						}
						if(depend.mod == PM_DEP_ANY) {
							/* accept any version */
							found = 1;
						} else {
							char *ver = strdup(p->version);
							/* check for a release in depend.version.  if it's
							 * missing remove it from p->version as well.
							 */
							if(!index(depend.version,'-')) {
								char *ptr;
								for(ptr = ver; *ptr != '-'; ptr++);
								*ptr = '\0';
							}
							cmp = rpmvercmp(ver, depend.version);
							switch(depend.mod) {
								case PM_DEP_EQ: found = (cmp == 0); break;
								case PM_DEP_GE: found = (cmp >= 0); break;
								case PM_DEP_LE: found = (cmp <= 0); break;
							}
							FREE(ver);
						}
					}
					for(lp = k; lp; lp = lp->next) {
						lp->data = NULL;
					}
					pm_list_free(k);
				}
				/* else if still not found... */
				if(!found) {
					MALLOC(miss, sizeof(pmdepmissing_t));
					miss->type = PM_DEP_DEPEND;
					miss->depend.mod = depend.mod;
					strncpy(miss->target, tp->name, 256);
					strncpy(miss->depend.name, depend.name, 256);
					strncpy(miss->depend.version, depend.version, 64);
					if(!pm_list_is_ptrin(baddeps, miss)) {
						baddeps = pm_list_add(baddeps, miss);
					}
				}
			}
		}
	} else if(op == PM_TRANS_TYPE_REMOVE) {
		/* check requiredby fields */
		for(i = packages; i; i = i->next) {
			pmpkg_t *tp;
			if(i->data == NULL) {
				continue;
			}
			tp = (pmpkg_t*)i->data;
			for(j = tp->requiredby; j; j = j->next) {
				if(!pm_list_is_strin((char *)j->data, packages)) {
					MALLOC(miss, sizeof(pmdepmissing_t));
					miss->type = PM_DEP_REQUIRED;
					miss->depend.mod = PM_DEP_ANY;
					miss->depend.version[0] = '\0';
					strncpy(miss->target, tp->name, 256);
					strncpy(miss->depend.name, (char *)j->data, 256);
					if(!pm_list_is_ptrin(baddeps, miss)) {
						baddeps = pm_list_add(baddeps, miss);
					}
				}
			}
		}
	}

	return(baddeps);
}

int splitdep(char *depstr, pmdepend_t *depend)
{
	char *str = NULL;
	char *ptr = NULL;

	if(depstr == NULL || depend == NULL) {
		return(-1);
	}

	depend->mod = 0;
	depend->name[0] = 0;
	depend->version[0] = 0;

	str = strdup(depstr);

	if((ptr = strstr(str, ">="))) {
		depend->mod = PM_DEP_GE;
	} else if((ptr = strstr(str, "<="))) {
		depend->mod = PM_DEP_LE;
	} else if((ptr = strstr(str, "="))) {
		depend->mod = PM_DEP_EQ;
	} else {
		/* no version specified - accept any */
		depend->mod = PM_DEP_ANY;
		strncpy(depend->name, str, sizeof(depend->name));
		strncpy(depend->version, "", sizeof(depend->version));
	}

	if(ptr == NULL) {
		FREE(str);
		return(0);
	}
	*ptr = '\0';
	strncpy(depend->name, str, sizeof(depend->name));
	ptr++;
	if(depend->mod != PM_DEP_EQ) {
		ptr++;
	}
	strncpy(depend->version, ptr, sizeof(depend->version));
	FREE(str);

	return(0);
}

/* return a new PMList target list containing all packages in the original
 * target list, as well as all their un-needed dependencies.  By un-needed,
 * I mean dependencies that are *only* required for packages in the target
 * list, so they can be safely removed.  This function is recursive.
 */
PMList* removedeps(pmdb_t *db, PMList *targs)
{
	PMList *i, *j, *k;
	PMList *newtargs = targs;

	if(db == NULL) {
		return(newtargs);
	}

	for(i = targs; i; i = i->next) {
		pmpkg_t *pkg = (pmpkg_t*)i->data;
		for(j = pkg->depends; j; j = j->next) {
			pmdepend_t depend;
			pmpkg_t *dep;
			int needed = 0;
			splitdep(j->data, &depend);
			dep = db_scan(db, depend.name, INFRQ_DESC | INFRQ_DEPENDS);
			if(pkg_isin(dep, targs)) {
				continue;
			}
			/* see if it was explicitly installed */
			if(dep->reason == PM_PKG_REASON_EXPLICIT) {
				/* ORE
				vprint("excluding %s -- explicitly installed\n", dep->name);*/
				needed = 1;
			}
			/* see if other packages need it */
			for(k = dep->requiredby; k && !needed; k = k->next) {
				pmpkg_t *dummy = db_scan(db, k->data, INFRQ_DESC);
				if(!pkg_isin(dummy, targs)) {
					needed = 1;
				}
			}
			if(!needed) {
				/* add it to the target list */
				pkg_free(dep);
				dep = db_scan(db, depend.name, INFRQ_ALL);
				newtargs = pm_list_add(newtargs, dep);
				newtargs = removedeps(db, newtargs);
			}
		}
	}

	return(newtargs);
}

/* populates *list with packages that need to be installed to satisfy all
 * dependencies (recursive) for *syncpkg->pkg
 *
 * make sure *list and *trail are already initialized
 */
int resolvedeps(pmdb_t *local, PMList *databases, pmsync_t *sync, PMList *list, PMList *trail, PMList **data)
{
	PMList *i, *j;
	PMList *targ = NULL;
	PMList *deps = NULL;

	targ = pm_list_add(targ, sync->spkg);
	deps = checkdeps(local, PM_TRANS_TYPE_ADD, targ);
	targ->data = NULL;
	pm_list_free(targ);

	if(deps == NULL) {
		return(0);
	}

	for(i = deps; i; i = i->next) {
		int found = 0;
		pmdepmissing_t *miss = i->data;

		/* XXX: conflicts are now treated specially in the _add and _sync functions */

		/*if(miss->type == CONFLICT) {
			fprintf(stderr, "error: cannot resolve dependencies for \"%s\":\n", miss->target);
			fprintf(stderr, "       %s conflicts with %s\n", miss->target, miss->depend.name);
			return(1);
		} else*/

		if(miss->type == PM_DEP_DEPEND) {
			pmsync_t *sync = NULL;

			/* find the package in one of the repositories */

			/* check literals */
			for(j = databases; !sync && j; j = j->next) {
				PMList *k;
				pmdb_t *dbs = j->data;

				for(k = db_get_pkgcache(dbs); !sync && k; k = k->next) {
					pmpkg_t *pkg = k->data;

					if(!strcmp(miss->depend.name, pkg->name)) {
						sync = sync_new(PM_SYSUPG_DEPEND, NULL, k->data);
						if(sync == NULL) {
							pm_errno = PM_ERR_MEMORY;
							goto error;
						}
						/* ORE
						sync->pkg->reason = PM_PKG_REASON_DEPEND;*/
					}
				}
			}

			/* check provides */
			/* ORE
			for(j = databases; !s && j; j = j->next) {
				PMList *provides;

				provides = _alpm_db_whatprovides(j->data, miss->depend.name);
				if(provides) {
					s = sync_new(PM_SYSUPG_DEPEND, NULL, !!!provides->data!!!);
					if(s == NULL) {
						pm_errno = PM_ERR_MEMORY;
						goto error;
					}
					sync->pkg->reason = PM_PKG_REASON_DEPEND;
				}
				FREELIST(provides);
			}*/

			if(sync == NULL) {
				pmdepmissing_t *m = (pmdepmissing_t *)malloc(sizeof(pmdepmissing_t));
				if(m == NULL) {
					/* ORE
					Free memory before leaving */
					pm_errno = PM_ERR_MEMORY;
					goto error;
				}
				*m = *(pmdepmissing_t *)i->data;
				*data = pm_list_add(*data, m);
				continue;
			}

			if(*data) {
				/* there is at least an unresolvable dep... so we only
				 * continue to get the whole list of unresolvable deps */
				continue;
			}

			found = 0;
			for(j = list; j && !found; j = j->next) {
				pmsync_t *tmp = j->data;

				if(tmp && !strcmp(tmp->spkg->name, sync->spkg->name)) {
					found = 1;
				}
			}

			if(found) {
				/* this dep is already in the target list */
				FREE(sync);
				continue;
			}

			_alpm_log(PM_LOG_FLOW2, "resolving %s", sync->spkg->name);
			found = 0;
			for(j = trail; j; j = j->next) {
				pmsync_t *tmp = j->data;

				if(tmp && !strcmp(tmp->spkg->name, sync->spkg->name)) {
					found = 1;
				}
			}

			if(!found) {
				/* check pmo_ignorepkg and pmo_s_ignore to make sure we haven't pulled in
				 * something we're not supposed to.
				 */
				int usedep = 1;	
				found = 0;
				/* ORE
				for(j = pmo_ignorepkg; j && !found; j = j->next) {
					if(!strcmp(j->data, sync->pkg->name)) {
						found = 1;
					}
				}
				for(j = pmo_s_ignore; j && !found; j = j->next) {
					if(!strcmp(j->data, sync->pkg->name)) {
						found = 1;
					}
				}
				if(found) {
					usedep = yesno("%s requires %s, but it is in IgnorePkg.  Install anyway? [Y/n] ",
						miss->target, sync->pkg->name);
				}*/
				if(usedep) {
					trail = pm_list_add(trail, sync);
					if(resolvedeps(local, databases, sync, list, trail, data)) {
						goto error;
					}
					_alpm_log(PM_LOG_FLOW2, "adding %s-%s", sync->spkg->name, sync->spkg->version);
					list = pm_list_add(list, sync);
				} else {
					_alpm_log(PM_LOG_ERROR, "cannot resolve dependencies for \"%s\"", miss->target);
					pm_errno = PM_ERR_UNRESOLVABLE_DEPS;
					goto error;
				}
			} else {
				/* cycle detected -- skip it */
				_alpm_log(PM_LOG_FLOW2, "dependency cycle detected: %s", sync->spkg->name);
				FREE(sync);
			}
		}
	}

	FREELIST(deps);

	if(*data) {
		pm_errno = PM_ERR_UNRESOLVABLE_DEPS;
		return(-1);
	}

	return(0);

error:
	FREELIST(deps);
	return(-1);
}

/* vim: set ts=2 sw=2 noet: */

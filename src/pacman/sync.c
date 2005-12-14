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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#ifdef CYGWIN
#include <limits.h> /* PATH_MAX */
#endif

#include <alpm.h>
/* pacman */
#include "util.h"
#include "log.h"
#include "download.h"
#include "list.h"
#include "package.h"
#include "db.h"
#include "trans.h"
#include "sync.h"
#include "pacman.h"
#include "conf.h"

extern config_t *config;

extern PM_DB *db_local;
extern list_t *pmc_syncs;

extern int maxcols;

static int sync_cleancache(int level)
{
	char *root, *cachedir;
	char dirpath[PATH_MAX];

	alpm_get_option(PM_OPT_ROOT, (long *)&root);
	alpm_get_option(PM_OPT_CACHEDIR, (long *)&cachedir);

	snprintf(dirpath, PATH_MAX, "%s%s", root, cachedir);

	if(level == 1) {
		/* incomplete cleanup: we keep latest packages and partial downloads */
		DIR *dir;
		struct dirent *ent;
		list_t *cache = NULL;
		list_t *clean = NULL;
		list_t *i, *j;

		if(!yesno("Do you want to remove old packages from cache? [Y/n] "))
			return(0);
		MSG(NL, "removing old packages from cache... ");
		dir = opendir(dirpath);
		if(dir == NULL) {
			ERR(NL, "could not access cache directory\n");
			return(1);
		}
		rewinddir(dir);
		while((ent = readdir(dir)) != NULL) {
			if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
				continue;
			}
			cache = list_add(cache, strdup(ent->d_name));
		}
		closedir(dir);

		for(i = cache; i; i = i->next) {
			char *str = i->data;
			char name[256], version[64];

			if(strstr(str, PM_EXT_PKG) == NULL) {
				clean = list_add(clean, strdup(str));
				continue;
			}
			/* we keep partially downloaded files */
			if(strstr(str, PM_EXT_PKG ".part")) {
				continue;
			}
			if(split_pkgname(str, name, version) != 0) {
				clean = list_add(clean, strdup(str));
				continue;
			}
			for(j = i->next; j; j = j->next) {
				char *s = j->data;
				char n[256], v[64];

				if(strstr(s, PM_EXT_PKG) == NULL) {
					continue;
				}
				if(strstr(s, PM_EXT_PKG ".part")) {
					continue;
				}
				if(split_pkgname(s, n, v) != 0) {
					continue;
				}
				if(!strcmp(name, n)) {
					char *ptr = (alpm_pkg_vercmp(version, v) < 0) ? str : s;
					if(!list_is_strin(ptr, clean)) {
						clean = list_add(clean, strdup(ptr));
					}
				}
			}
		}
		FREELIST(cache);

		for(i = clean; i; i = i->next) {
			char path[PATH_MAX];

			snprintf(path, PATH_MAX, "%s/%s", dirpath, (char *)i->data);
			unlink(path);
		}
		FREELIST(clean);
	} else {
		/* full cleanup */
		if(!yesno("Do you want to remove all packages from cache? [Y/n] "))
			return(0);
		MSG(NL, "removing all packages from cache... ");

		if(rmrf(dirpath)) {
			ERR(NL, "could not remove cache directory\n");
			return(1);
		}

		if(makepath(dirpath)) {
			ERR(NL, "could not create new cache directory\n");
			return(1);
		}
	}

	MSG(CL, "done.\n");
	return(0);
}

static int sync_synctree(list_t *syncs)
{
	char *root, *dbpath;
	char path[PATH_MAX];
	list_t *i;
	int success = 0, ret;

	alpm_get_option(PM_OPT_ROOT, (long *)&root);
	alpm_get_option(PM_OPT_DBPATH, (long *)&dbpath);

	for(i = syncs; i; i = i->next) {
		list_t *files = NULL;
		char newmtime[16] = "";
		char *lastupdate;
		sync_t *sync = (sync_t *)i->data;

		/* get the lastupdate time */
		lastupdate = alpm_db_getinfo(sync->db, PM_DB_LASTUPDATE);
		if(lastupdate == NULL) {
			vprint("failed to get lastupdate time for %s (no big deal)\n", sync->treename);
		}

		/* build a one-element list */
		snprintf(path, PATH_MAX, "%s" PM_EXT_DB, sync->treename);
		files = list_add(files, strdup(path));

		snprintf(path, PATH_MAX, "%s%s", root, dbpath);

		ret = downloadfiles_forreal(sync->servers, path, files, (const char *)&lastupdate, newmtime);
		vprint("sync: new mtime for %s: %s\n", sync->treename, newmtime);
		FREELIST(files);
		if(ret > 0) {
			ERR(NL, "failed to synchronize %s\n", sync->treename);
			success--;
		} else if(ret < 0) {
			MSG(NL, " %s is up to date\n", sync->treename);
		} else {
			snprintf(path, PATH_MAX, "%s%s/%s" PM_EXT_DB, root, dbpath, sync->treename);
			if(alpm_db_update(sync->db, path, newmtime) == -1) {
				ERR(NL, "failed to synchronize %s (%s)\n", sync->treename, alpm_strerror(pm_errno));
				success--;
			}
			/* remove the .tar.gz */
			unlink(path);
		}
	}

	return(success);
}

static int sync_search(list_t *syncs, list_t *targets)
{
	list_t *i;

	for(i = syncs; i; i = i->next) {
		sync_t *sync = i->data;
		if(targets) {
			if(db_search(sync->db, sync->treename, targets)) {
				return(1);
			}
		} else {
			PM_LIST *lp;

			for(lp = alpm_db_getpkgcache(sync->db); lp; lp = alpm_list_next(lp)) {
				PM_PKG *pkg = alpm_list_getdata(lp);

				MSG(NL, "%s/%s %s\n    ", sync->treename, (char *)alpm_pkg_getinfo(pkg, PM_PKG_NAME), (char *)alpm_pkg_getinfo(pkg, PM_PKG_VERSION));
				indentprint(alpm_pkg_getinfo(pkg, PM_PKG_DESC), 4);
				MSG(NL, "\n");
			}
		}
	}

	return(0);
}

static int sync_group(list_t *syncs, list_t *targets)
{
	list_t *i, *j;
	
	if(targets) {
		for(i = targets; i; i = i->next) {
			for(j = syncs; j; j = j->next) {
				sync_t *sync = j->data;
				PM_GRP *grp = alpm_db_readgrp(sync->db, i->data);

				if(grp) {
					MSG(NL, "%s/%s\n", sync->treename, (char *)alpm_grp_getinfo(grp, PM_GRP_NAME));
					PM_LIST_display("   ", alpm_grp_getinfo(grp, PM_GRP_PKGNAMES));
				}
			}
		}
	} else {
		for(j = syncs; j; j = j->next) {
			sync_t *sync = j->data;
			PM_LIST *lp;

			for(lp = alpm_db_getpkgcache(sync->db); lp; lp = alpm_list_next(lp)) {
				PM_GRP *grp = alpm_list_getdata(lp);

				MSG(NL, "%s/%s\n", (char *)sync->treename, (char *)alpm_grp_getinfo(grp, PM_GRP_NAME));
				PM_LIST_display("   ", alpm_grp_getinfo(grp, PM_GRP_PKGNAMES));
			}
		}
	}

	return(0);
}

static int sync_info(list_t *syncs, list_t *targets)
{
	list_t *i, *j;

	if(targets) {
		for(i = targets; i; i = i->next) {
			int found = 0;

			for(j = syncs; j && !found; j = j->next) {
				sync_t *sync = j->data;
				PM_LIST *lp;

				for(lp = alpm_db_getpkgcache(sync->db); !found && lp; lp = alpm_list_next(lp)) {
					PM_PKG *pkg = alpm_list_getdata(lp);

					if(!strcmp(alpm_pkg_getinfo(pkg, PM_PKG_NAME), i->data)) {
						dump_pkg_sync(pkg, sync->treename);
						MSG(NL, "\n");
						found = 1;
					}
				}
			}
			if(!found) {
				ERR(NL, "package \"%s\" was not found.\n", (char *)i->data);
				break;
			}
		}
	} else {
		for(j = syncs; j; j = j->next) {
			sync_t *sync = j->data;
			PM_LIST *lp;
			
			for(lp = alpm_db_getpkgcache(sync->db); lp; lp = alpm_list_next(lp)) {
				dump_pkg_sync(alpm_list_getdata(lp), sync->treename);
				MSG(NL, "\n");
			}
		}
	}

	return(0);
}

static int sync_list(list_t *syncs, list_t *targets)
{
	list_t *i;
	list_t *ls = NULL;

	if(targets) {
		for(i = targets; i; i = i->next) {
			list_t *j;
			sync_t *sync = NULL;

			for(j = syncs; j && !sync; j = j->next) {
				sync_t *s = j->data;

				if(strcmp(i->data, s->treename) == 0) {
					sync = s;
				}
			}

			if(sync == NULL) {
				ERR(NL, "repository \"%s\" was not found.\n", (char *)i->data);
				for(j = ls; j; j = j->next) {
					j->data = NULL;
				}
				list_free(ls);
				return(1);
			}

			ls = list_add(ls, sync);
		}
	} else {
		ls = syncs;
	}

	for(i = ls; i; i = i->next) {
		PM_LIST *lp;
		sync_t *sync = i->data;

		for(lp = alpm_db_getpkgcache(sync->db); lp; lp = alpm_list_next(lp)) {
			PM_PKG *pkg = alpm_list_getdata(lp);

			MSG(NL, "%s %s %s\n", (char *)sync->treename, (char *)alpm_pkg_getinfo(pkg, PM_PKG_NAME), (char *)alpm_pkg_getinfo(pkg, PM_PKG_VERSION));
		}
	}

	if(targets) {
		for(i = ls; i; i = i->next) {
			i->data = NULL;
		}
		list_free(ls);
	}

	return(0);
}

int pacman_sync(list_t *targets)
{
	int confirm = 0;
	int retval = 0;
	list_t *i;
	PM_LIST *packages, *data, *lp;
	char *root, *cachedir;
	char ldir[PATH_MAX];
	int varcache = 1;
	list_t *files = NULL;

	if(pmc_syncs == NULL || !list_count(pmc_syncs)) {
		ERR(NL, "no usable package repositories configured.\n");
		return(1);
	}

	if(config->op_s_clean) {
		return(sync_cleancache(config->op_s_clean));
	}

	/* open the database(s) */
	for(i = pmc_syncs; i; i = i->next) {
		sync_t *sync = i->data;
		sync->db = alpm_db_register(sync->treename);
		if(sync->db == NULL) {
			ERR(NL, "%s\n", alpm_strerror(pm_errno));
			return(1);
		}
	}

	if(config->op_s_sync) {
		/* grab a fresh package list */
		MSG(NL, ":: Synchronizing package databases...\n");
		alpm_logaction("synchronizing package lists");
		if(sync_synctree(pmc_syncs)) {
			return(1);
		}
	}

	if(config->op_s_search) {
		return(sync_search(pmc_syncs, targets));
	}

	if(config->group) {
		return(sync_group(pmc_syncs, targets));
	}

	if(config->op_s_info) {
		return(sync_info(pmc_syncs, targets));
	}

	if(config->op_q_list) {
		return(sync_list(pmc_syncs, targets));
	}

	/* Step 1: create a new transaction...
	 */
	if(alpm_trans_init(PM_TRANS_TYPE_SYNC, config->flags, cb_trans_evt, cb_trans_conv) == -1) {
		ERR(NL, "failed to init transaction (%s)\n", alpm_strerror(pm_errno));
		retval = 1;
		goto cleanup;
	}

	if(config->op_s_upgrade) {
		MSG(NL, ":: Starting local database upgrade...\n");
		alpm_logaction("starting full system upgrade");
		if(alpm_trans_sysupgrade() == -1) {
			ERR(NL, "%s\n", alpm_strerror(pm_errno));
			retval = 1;
			goto cleanup;
		}

		/* check if pacman itself is one of the packages to upgrade.  If so, we
		 * we should upgrade ourselves first and then re-exec as the new version.
		 *
		 * this can prevent some of the "syntax error" problems users can have
		 * when sysupgrade'ing with an older version of pacman.
		 */
		data = alpm_trans_getinfo(PM_TRANS_PACKAGES);
		for(lp = alpm_list_first(data); lp; lp = alpm_list_next(lp)) {
			PM_SYNCPKG *sync = alpm_list_getdata(lp);
			PM_PKG *spkg = alpm_sync_getinfo(sync, PM_SYNC_PKG);
			if(!strcmp("pacman", alpm_pkg_getinfo(spkg, PM_PKG_NAME))) {
				MSG(NL, "\n:: pacman has detected a newer version of the \"pacman\" package.\n");
				MSG(NL, ":: It is recommended that you allow pacman to upgrade itself\n");
				MSG(NL, ":: first, then you can re-run the operation with the newer version.\n");
				MSG(NL, "::\n");
				if(!yesno(":: Upgrade anyway? [Y/n] ")) {
					retval = 0;
					alpm_trans_release();
					goto cleanup;
				}
			}
		}
	} else {
		/* process targets */
		for(i = targets; i; i = i->next) {
			char *targ = i->data;
			if(alpm_trans_addtarget(targ) == -1) {
				PM_GRP *grp = NULL;
				list_t *j;
				if(pm_errno != PM_ERR_PKG_NOT_FOUND) {
					ERR(NL, "could not add target '%s': %s\n", (char *)i->data, alpm_strerror(pm_errno));
					retval = 1;
					goto cleanup;
				}
				/* target not found: check if it's a group */
				for(j = pmc_syncs; j && !grp; j = j->next) {
					sync_t *sync = j->data;
					grp = alpm_db_readgrp(sync->db, targ);
					if(grp) {
						PM_LIST *pmpkgs;
						list_t *k, *pkgs;
						MSG(NL, ":: group %s:\n", targ);
						pmpkgs = alpm_grp_getinfo(grp, PM_GRP_PKGNAMES);
						/* remove dupe entries in case a package exists in multiple repos */
						/*   (the dupe function takes a PM_LIST* and returns a list_t*) */
						pkgs = PM_LIST_remove_dupes(pmpkgs);
						list_display("   ", pkgs);
						if(yesno(":: Install whole content? [Y/n] ")) {
							for(k = pkgs; k; k = k->next) {
								targets = list_add(targets, strdup(k->data));
							}
						} else {
							for(k = pkgs; k; k = k->next) {
								char *pkgname = k->data;
								if(yesno(":: Install %s from group %s? [Y/n] ", pkgname, targ)) {
									targets = list_add(targets, strdup(pkgname));
								}
							}
						}
						FREELIST(pkgs);
					}
				}
				if(grp == NULL) {
					/* targ not found in sync db, searching for providers... */
					PM_LIST *k = NULL;
					PM_PKG *pkg;
					char *pname;
					for(j = pmc_syncs; j && !k; j = j->next) {
						sync_t *sync = j->data;
						k = alpm_db_whatprovides(sync->db, targ);
						pkg = (PM_PKG*)alpm_list_getdata(alpm_list_first(k));
						pname = (char*)alpm_pkg_getinfo(pkg, PM_PKG_NAME);
					}
					if(pname != NULL) {
						/* targ is provided by pname */
						targets = list_add(targets, strdup(pname));
					} else {
						ERR(NL, "could not add target '%s': not found in sync db\n", targ);
						retval = 1;
						goto cleanup;
					}
				}
			}
		}
	}

	/* Step 2: "compute" the transaction based on targets and flags */
	if(alpm_trans_prepare(&data) == -1) {
		ERR(NL, "failed to prepare transaction (%s)\n", alpm_strerror(pm_errno));
		retval = 1;
		goto cleanup;
	}

	/* list targets and get confirmation */
	if(!config->op_s_printuris) {
		list_t *list = NULL;
		char *str;
		unsigned long totalsize = 0;
		double mb;

		packages = alpm_trans_getinfo(PM_TRANS_PACKAGES);
		if(packages == NULL) {
			retval = 0;
			goto cleanup;
		}

		for(lp = alpm_list_first(packages); lp; lp = alpm_list_next(lp)) {
			PM_SYNCPKG *sync = alpm_list_getdata(lp);
			if((int)alpm_sync_getinfo(sync, PM_SYNC_TYPE) == PM_SYNC_TYPE_REPLACE) {
				PM_LIST *j, *data;
				data = alpm_sync_getinfo(sync, PM_SYNC_DATA);
				for(j = alpm_list_first(data); j; j = alpm_list_next(j)) {
					PM_PKG *p = alpm_list_getdata(j);
					char *pkgname = alpm_pkg_getinfo(p, PM_PKG_NAME);
					if(!list_is_strin(pkgname, list)) {
						list = list_add(list, strdup(pkgname));
					}
				}
			}
		}
		if(list) {
			printf("\nRemove:  ");
			str = buildstring(list);
			indentprint(str, 9);
			printf("\n");
			FREELIST(list);
			FREE(str);
		}
		for(lp = alpm_list_first(packages); lp; lp = alpm_list_next(lp)) {
			char *pkgname, *pkgver;
			PM_SYNCPKG *sync = alpm_list_getdata(lp);
			PM_PKG *pkg = alpm_sync_getinfo(sync, PM_SYNC_PKG);

			pkgname = alpm_pkg_getinfo(pkg, PM_PKG_NAME);
			pkgver = alpm_pkg_getinfo(pkg, PM_PKG_VERSION);

			asprintf(&str, "%s-%s", pkgname, pkgver);
			list = list_add(list, str);

			totalsize += (int)alpm_pkg_getinfo(pkg, PM_PKG_SIZE);
		}
		mb = (double)(totalsize / 1048576.0);
		/* round up to 0.1 */
		if(mb < 0.1) {
			mb = 0.1;
		}
		MSG(NL, "\nTargets: ");
		str = buildstring(list);
		indentprint(str, 9);
		MSG(NL, "\nTotal Package Size:   %.1f MB\n", mb);
		FREELIST(list);
		FREE(str);

		if(config->op_s_downloadonly) {
			if(config->noconfirm) {
				MSG(NL, "\nBeginning download...\n");
				confirm = 1;
			} else {
				MSG(NL, "\n");
				confirm = yesno("Proceed with download? [Y/n] ");
			}
		} else {
			/* don't get any confirmation if we're called from makepkg */
			if(config->op_d_resolve) {
				confirm = 1;
			} else {
				if(config->noconfirm) {
					MSG(NL, "\nBeginning upgrade process...\n");
					confirm = 1;
				} else {
					MSG(NL, "\n");
					confirm = yesno("Proceed with upgrade? [Y/n] ");
				}
			}
		}
		if(!confirm) {
			retval = 1;
			goto cleanup;
		}
	}

	/* group sync records by repository and download */
	alpm_get_option(PM_OPT_ROOT, (long *)&root);
	alpm_get_option(PM_OPT_CACHEDIR, (long *)&cachedir);
	snprintf(ldir, PATH_MAX, "%s%s", root, cachedir);

	for(i = pmc_syncs; i; i = i->next) {
		sync_t *current = i->data;

		for(lp = alpm_list_first(packages); lp; lp = alpm_list_next(lp)) {
			PM_SYNCPKG *sync = alpm_list_getdata(lp);
			PM_PKG *spkg = alpm_sync_getinfo(sync, PM_SYNC_PKG);
			PM_DB *dbs = alpm_pkg_getinfo(spkg, PM_PKG_DATA);

			if(current->db == dbs) {
				struct stat buf;
				char path[PATH_MAX];
				char *pkgname, *pkgver, *pkgarch;

				pkgname = alpm_pkg_getinfo(spkg, PM_PKG_NAME);
				pkgver = alpm_pkg_getinfo(spkg, PM_PKG_VERSION);
				pkgarch = alpm_pkg_getinfo(spkg, PM_PKG_ARCH);

				if(config->op_s_printuris) {
					server_t *server = (server_t*)current->servers->data;
					snprintf(path, PATH_MAX, "%s-%s-%s" PM_EXT_PKG, pkgname, pkgver, pkgarch);
					if(!strcmp(server->protocol, "file")) {
						MSG(NL, "%s://%s%s\n", server->protocol, server->path, path);
					} else {
						MSG(NL, "%s://%s%s%s\n", server->protocol,
						    server->server, server->path, path);
					}
				} else {
					snprintf(path, PATH_MAX, "%s/%s-%s-%s" PM_EXT_PKG, ldir, pkgname, pkgver, pkgarch);
					if(stat(path, &buf)) {
						/* file is not in the cache dir, so add it to the list */
						snprintf(path, PATH_MAX, "%s-%s-%s" PM_EXT_PKG, pkgname, pkgver, pkgarch);
						files = list_add(files, strdup(path));
					} else {
						vprint(" %s-%s-%s" PM_EXT_PKG " is already in the cache\n", pkgname, pkgver, pkgarch);
					}
				}
			}
		}

		if(files) {
			struct stat buf;
			MSG(NL, "\n:: Retrieving packages from %s...\n", current->treename);
			fflush(stdout);
			if(stat(ldir, &buf)) {
				/* no cache directory.... try creating it */
				MSG(NL, "warning: no %s cache exists.  creating...\n", ldir);
				alpm_logaction("warning: no %s cache exists.  creating...", ldir);
				if(makepath(ldir)) {
					/* couldn't mkdir the cache directory, so fall back to /tmp and unlink
					 * the package afterwards.
					 */
					MSG(NL, "warning: couldn't create package cache, using /tmp instead");
					alpm_logaction("warning: couldn't create package cache, using /tmp instead");
					snprintf(ldir, PATH_MAX, "/tmp");
					varcache = 0;
				}
			}
			if(downloadfiles(current->servers, ldir, files)) {
				ERR(NL, "failed to retrieve some files from %s\n", current->treename);
				retval = 1;
				goto cleanup;
			}
			FREELIST(files);
		}
	}
	if(config->op_s_printuris) {
		goto cleanup;
	}
	MSG(NL, "\n");

	/* Check integrity of files */
	MSG(NL, "checking package integrity... ");

	for(lp = alpm_list_first(packages); lp; lp = alpm_list_next(lp)) {
		PM_SYNCPKG *sync = alpm_list_getdata(lp);
		PM_PKG *spkg = alpm_sync_getinfo(sync, PM_SYNC_PKG);
		char str[PATH_MAX], pkgname[PATH_MAX];
		char *md5sum1, *md5sum2, *sha1sum1, *sha1sum2;

		snprintf(pkgname, PATH_MAX, "%s-%s.%s" PM_EXT_PKG,
		                            (char *)alpm_pkg_getinfo(spkg, PM_PKG_NAME),
		                            (char *)alpm_pkg_getinfo(spkg, PM_PKG_VERSION),
		                            (char *)alpm_pkg_getinfo(spkg, PM_PKG_ARCH));
		md5sum1 = alpm_pkg_getinfo(spkg, PM_PKG_MD5SUM);
		sha1sum1 = alpm_pkg_getinfo(spkg, PM_PKG_SHA1SUM);

		if((md5sum1 == NULL) && (sha1sum1 == NULL)) {
			ERR(NL, "can't get md5 or sha1 checksum for package %s\n", pkgname);
			retval = 1;
			continue;
		}
		snprintf(str, PATH_MAX, "%s/%s", ldir, pkgname);
		md5sum2 = alpm_get_md5sum(str);
		sha1sum2 = alpm_get_sha1sum(str);
		if(md5sum2 == NULL && sha1sum2 == NULL) {
			ERR(NL, "can't get md5 or sha1 checksum for package %s\n", pkgname);
			retval = 1;
			continue;
		}
		if((strcmp(md5sum1, md5sum2) != 0) && (strcmp(sha1sum1, sha1sum2) != 0)) {
			retval = 1;
			ERR(NL, "archive %s is corrupted (bad MD5 or SHA1 checksum)\n", pkgname);
		}
		FREE(md5sum2);
		FREE(sha1sum2);
	}
	if(retval) {
		goto cleanup;
	}
	MSG(CL, "done.\n");

	if(config->op_s_downloadonly) {
		goto cleanup;
	}

	/* Step 3: actually perform the installation */
	if(alpm_trans_commit() == -1) {
		ERR(NL, "failed to commit transaction (%s)\n", alpm_strerror(pm_errno));
		retval = 1;
		goto cleanup;
	}

	if(!varcache && !config->op_s_downloadonly) {
		/* delete packages */
		for(i = files; i; i = i->next) {
			unlink(i->data);
		}
	}

cleanup:
	alpm_trans_release();
	return(retval);

}

/* vim: set ts=2 sw=2 noet: */

/*
 *  trans.c
 *
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2005 by Christian Hamar <krics@linuxforum.hu>
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

#include "config.h"

#include "trans.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libintl.h>

/* pacman-g2 */
#include "backup.h"
#include "deps.h"
#include "error.h"
#include "md5.h"
#include "package.h"
#include "provide.h"
#include "sha1.h"
#include "util.h"
#include "log.h"
#include "list.h"
#include "handle.h"
#include "add.h"
#include "remove.h"
#include "sync.h"
#include "cache.h"
#include "pacman.h"

#include "trans_sysupgrade.h"

static int check_oldcache(void)
{
	pmdb_t *db = handle->db_local;
	char lastupdate[16] = "";

	if(_pacman_db_getlastupdate(db, lastupdate) == -1) {
		return(-1);
	}
	if(strlen(db->lastupdate) && strcmp(lastupdate, db->lastupdate) != 0) {
		_pacman_log(PM_LOG_DEBUG, _("cache for '%s' repo is too old"), db->treename);
		_pacman_db_free_pkgcache(db);
	} else {
		_pacman_log(PM_LOG_DEBUG, _("cache for '%s' repo is up to date"), db->treename);
	}
	return(0);
}

pmtrans_t *_pacman_trans_new()
{
	pmtrans_t *trans = _pacman_zalloc(sizeof(pmtrans_t));

	if(trans) {
		trans->state = STATE_IDLE;
	}

	return(trans);
}

void _pacman_trans_free(pmtrans_t *trans)
{
	if(trans == NULL) {
		return;
	}

	FREELIST(trans->targets);
	if(trans->type == PM_TRANS_TYPE_SYNC) {
		pmlist_t *i;
		for(i = trans->packages; i; i = i->next) {
			FREESYNC(i->data);
		}
		FREELIST(trans->packages);
	} else {
		FREELISTPKGS(trans->packages);
	}

	FREELIST(trans->skiplist);

	_pacman_trans_fini(trans);
	free(trans);
}

int _pacman_trans_init(pmtrans_t *trans, pmtranstype_t type, unsigned int flags, pmtrans_cbs_t cbs)
{
	/* Sanity checks */
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));

	switch(type) {
		case PM_TRANS_TYPE_ADD:
		case PM_TRANS_TYPE_UPGRADE:
			trans->ops = &_pacman_add_pmtrans_opts;
		break;
		case PM_TRANS_TYPE_REMOVE:
			trans->ops = &_pacman_remove_pmtrans_opts;
		break;
		case PM_TRANS_TYPE_SYNC:
			trans->ops = &_pacman_sync_pmtrans_opts;
		break;
		default:
			trans->ops = NULL;
			// Be more verbose about the trans type
			_pacman_log(PM_LOG_ERROR,
					_("could not initialize transaction: Unknown Transaction Type %d"), type);
			return(-1);
	}

	trans->handle = handle;
	trans->type = type;
	trans->flags = flags;
	trans->cbs = cbs;
	trans->state = STATE_INITIALIZED;

	check_oldcache();

	return(0);
}

void _pacman_trans_fini(pmtrans_t *trans)
{
	if(trans !=NULL && trans->ops != NULL && trans->ops->fini != NULL) {
		trans->ops->fini(trans);
	}
}

int _pacman_trans_sysupgrade(pmtrans_t *trans)
{
	/* Sanity checks */
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));

	return(_pacman_sync_sysupgrade(trans, handle->db_local, handle->dbs_sync));
}

int _pacman_trans_addtarget(pmtrans_t *trans, const char *target)
{
	/* Sanity checks */
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->ops != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->ops->addtarget != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(target != NULL, RET_ERR(PM_ERR_WRONG_ARGS, -1));

	if(_pacman_list_is_strin(target, trans->targets)) {
		RET_ERR(PM_ERR_TRANS_DUP_TARGET, -1);
	}

	if(trans->ops->addtarget(trans, target) == -1) {
		/* pm_errno is set by trans->ops->addtarget() */
		return(-1);
	}

	trans->targets = _pacman_list_add(trans->targets, strdup(target));

	return(0);
}

int _pacman_trans_set_state(pmtrans_t *trans, int new_state)
{
	/* Sanity checks */
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));

	/* Ignore unchanged state */
	if (trans->state == new_state) {
		return(0);
	}

	if (trans->set_state != NULL) {
		if (trans->set_state(trans, new_state) == -1) {
			/* pm_errno is set by trans->state_changed() */
			return(-1);
		}
	}
	trans->state = new_state;

	return(0);
}

int _pacman_trans_prepare(pmtrans_t *trans, pmlist_t **data)
{
	/* Sanity checks */
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->ops != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->ops->prepare != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(data != NULL, RET_ERR(PM_ERR_WRONG_ARGS, -1));

	*data = NULL;

	/* If there's nothing to do, return without complaining */
	if(trans->packages == NULL) {
		return(0);
	}

	if(trans->ops->prepare(trans, data) == -1) {
		/* pm_errno is set by trans->ops->prepare() */
		return(-1);
	}

	_pacman_trans_set_state(trans, STATE_PREPARED);

	return(0);
}

/* Helper function for comparing strings
 */
static int str_cmp(const void *s1, const void *s2)
{
	return(strcmp(s1, s2));
}

int _pacman_remove_commit(pmtrans_t *trans, pmlist_t **data)
{
	struct stat buf;
	pmlist_t *lp;
	char line[PATH_MAX+1];
	pmdb_t *db = trans->handle->db_local;

	ASSERT(db != NULL, RET_ERR(PM_ERR_DB_NULL, -1));
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));

	const size_t package_count = _pacman_list_count(trans->packages);
	size_t package_index = 1;
	for(const pmlist_t *targ = trans->packages; targ; targ = targ->next, package_index++) {
		char pm_install[PATH_MAX];
		pmpkg_t *info = (pmpkg_t*)targ->data;

		if(handle->trans->state == STATE_INTERRUPTED) {
			break;
		}

		if(trans->type != PM_TRANS_TYPE_UPGRADE) {
			EVENT(trans, PM_TRANS_EVT_REMOVE_START, info, NULL);
			_pacman_log(PM_LOG_FLOW1, _("removing package %s-%s"), info->name, info->version);

			/* run the pre-remove scriptlet if it exists */
			if(info->scriptlet && !(trans->flags & PM_TRANS_FLAG_NOSCRIPTLET)) {
				snprintf(pm_install, PATH_MAX, "%s/%s-%s/install", db->path, info->name, info->version);
				_pacman_runscriptlet(handle->root, pm_install, "pre_remove", info->version, NULL, trans);
			}
		}

		if(!(trans->flags & PM_TRANS_FLAG_DBONLY)) {
			_pacman_log(PM_LOG_FLOW1, _("removing files"));

			const int file_count = _pacman_list_count(info->files);
			int file_index = 0;
			/* iterate through the list backwards, unlinking files */
			for(lp = _pacman_list_last(info->files); lp; lp = lp->prev, file_index++) {
				int nb = 0;
				char *file = lp->data;

				const double percent = (double)file_index / file_count;
				PROGRESS(trans, PM_TRANS_PROGRESS_REMOVE_START, info->name, (int)(percent * 100), package_count, package_index);

				char *hash = _pacman_needbackup(file, info->backup);
				if(hash != NULL) {
					nb = 1;
					FREE(hash);
				}
				if(!nb && trans->type == PM_TRANS_TYPE_UPGRADE) {
					/* check noupgrade */
					if(_pacman_list_is_strin(file, handle->noupgrade)) {
						nb = 1;
					}
				}
				snprintf(line, PATH_MAX, "%s%s", handle->root, file);
				if(lstat(line, &buf)) {
					_pacman_log(PM_LOG_DEBUG, _("file %s does not exist"), file);
					continue;
				}
				if(S_ISDIR(buf.st_mode)) {
					if(rmdir(line)) {
						/* this is okay, other packages are probably using it. */
						_pacman_log(PM_LOG_DEBUG, _("keeping directory %s"), file);
					} else {
						_pacman_log(PM_LOG_FLOW2, _("removing directory %s"), file);
					}
				} else {
					/* check the "skip list" before removing the file.
					 * see the big comment block in db_find_conflicts() for an
					 * explanation. */
					if (_pacman_list_is_strin(file, trans->skiplist)) {
						_pacman_log(PM_LOG_FLOW2, _("skipping removal of %s as it has moved to another package"),
							file);
					} else {
						/* if the file is flagged, back it up to .pacsave */
						if(nb) {
							if(trans->type == PM_TRANS_TYPE_UPGRADE) {
								/* we're upgrading so just leave the file as is. pacman_add() will handle it */
							} else {
								if(!(trans->flags & PM_TRANS_FLAG_NOSAVE)) {
									char newpath[PATH_MAX];
									snprintf(newpath, PATH_MAX, "%s.pacsave", line);
									rename(line, newpath);
									_pacman_log(PM_LOG_WARNING, _("%s saved as %s"), line, newpath);
									pacman_logaction(_("%s saved as %s"), line, newpath);
								} else {
									_pacman_log(PM_LOG_FLOW2, _("unlinking %s"), file);
									if(unlink(line)) {
										_pacman_log(PM_LOG_ERROR, _("cannot remove file %s"), file);
									}
								}
							}
						} else {
							_pacman_log(PM_LOG_FLOW2, _("unlinking %s"), file);
							if(unlink(line)) {
								_pacman_log(PM_LOG_ERROR, _("cannot remove file %s"), file);
							}
						}
					}
				}
			}
		}

		PROGRESS(trans, PM_TRANS_PROGRESS_REMOVE_START, info->name, 100, package_count, package_index);
		if(trans->type != PM_TRANS_TYPE_UPGRADE) {
			/* run the post-remove script if it exists */
			if(info->scriptlet && !(trans->flags & PM_TRANS_FLAG_NOSCRIPTLET)) {
				/* must run ldconfig here because some scriptlets fail due to missing libs otherwise */
				_pacman_ldconfig(handle->root);
				snprintf(pm_install, PATH_MAX, "%s/%s-%s/install", db->path, info->name, info->version);
				_pacman_runscriptlet(handle->root, pm_install, "post_remove", info->version, NULL, trans);
			}
		}

		/* remove the package from the database */
		_pacman_log(PM_LOG_FLOW1, _("updating database"));
		_pacman_log(PM_LOG_FLOW2, _("removing database entry '%s'"), info->name);
		if(_pacman_db_remove(db, info) == -1) {
			_pacman_log(PM_LOG_ERROR, _("could not remove database entry %s-%s"), info->name, info->version);
		}
		if(_pacman_db_remove_pkgfromcache(db, info) == -1) {
			_pacman_log(PM_LOG_ERROR, _("could not remove entry '%s' from cache"), info->name);
		}

		/* update dependency packages' REQUIREDBY fields */
		_pacman_log(PM_LOG_FLOW2, _("updating dependency packages 'requiredby' fields"));
		for(lp = info->depends; lp; lp = lp->next) {
			pmpkg_t *depinfo = NULL;
			pmdepend_t depend;
			char *data;
			if(_pacman_splitdep((char*)lp->data, &depend)) {
				continue;
			}
			/* if this dependency is in the transaction targets, no need to update
			 * its requiredby info: it is in the process of being removed (if not
			 * already done!)
			 */
			if(_pacman_pkg_isin(depend.name, trans->packages)) {
				continue;
			}
			depinfo = _pacman_db_get_pkgfromcache(db, depend.name);
			if(depinfo == NULL) {
				/* look for a provides package */
				pmlist_t *provides = _pacman_db_whatprovides(db, depend.name);
				if(provides) {
					/* TODO: should check _all_ packages listed in provides, not just
					 *			 the first one.
					 */
					/* use the first one */
					depinfo = _pacman_db_get_pkgfromcache(db, ((pmpkg_t *)provides->data)->name);
					FREELISTPTR(provides);
				}
				if(depinfo == NULL) {
					_pacman_log(PM_LOG_ERROR, _("could not find dependency '%s'"), depend.name);
					/* wtf */
					continue;
				}
			}
			/* splice out this entry from requiredby */
			depinfo->requiredby = _pacman_list_remove(_pacman_pkg_getinfo(depinfo, PM_PKG_REQUIREDBY), info->name, str_cmp, (void **)&data);
			FREE(data);
			_pacman_log(PM_LOG_DEBUG, _("updating 'requiredby' field for package '%s'"), depinfo->name);
			if(_pacman_db_write(db, depinfo, INFRQ_DEPENDS)) {
				_pacman_log(PM_LOG_ERROR, _("could not update 'requiredby' database entry %s-%s"),
					depinfo->name, depinfo->version);
			}
		}

		if(trans->type != PM_TRANS_TYPE_UPGRADE) {
			EVENT(trans, PM_TRANS_EVT_REMOVE_DONE, info, NULL);
		}
	}

	/* run ldconfig if it exists */
	if((trans->type != PM_TRANS_TYPE_UPGRADE) && (handle->trans->state != STATE_INTERRUPTED)) {
		_pacman_ldconfig(handle->root);
	}

	return(0);
}

int _pacman_add_commit(pmtrans_t *trans, pmlist_t **data)
{
	int i, ret = 0, errors = 0;
	int archive_ret;
	register struct archive *archive;
	struct archive_entry *entry;
	char expath[PATH_MAX], cwd[PATH_MAX] = "", *what;
	unsigned char cb_state;
	time_t t;
	pmlist_t *lp;
	pmdb_t *db = trans->handle->db_local;

	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(db != NULL, RET_ERR(PM_ERR_DB_NULL, -1));

	if(trans->packages == NULL) {
		return(0);
	}

	const size_t package_count = _pacman_list_count(trans->packages);
	size_t package_index = 1;
	for(const pmlist_t *targ = trans->packages; targ; targ = targ->next, package_index++) {
		unsigned short pmo_upgrade;
		char pm_install[PATH_MAX];
		pmpkg_t *info = (pmpkg_t *)targ->data;
		pmpkg_t *oldpkg = NULL;
		errors = 0;

		if(handle->trans->state == STATE_INTERRUPTED) {
			break;
		}

		pmo_upgrade = (trans->type == PM_TRANS_TYPE_UPGRADE) ? 1 : 0;

		/* see if this is an upgrade.  if so, remove the old package first */
		if(pmo_upgrade) {
			pmpkg_t *local = _pacman_db_get_pkgfromcache(db, info->name);
			if(local) {
				EVENT(trans, PM_TRANS_EVT_UPGRADE_START, info, NULL);
				cb_state = PM_TRANS_PROGRESS_UPGRADE_START;
				_pacman_log(PM_LOG_FLOW1, _("upgrading package %s-%s"), info->name, info->version);
				if((what = _pacman_strdup(info->name)) == NULL) {
					return -1;
				}

				/* we'll need to save some record for backup checks later */
				oldpkg = _pacman_pkg_new(local->name, local->version);
				if(oldpkg) {
					if(!(local->infolevel & INFRQ_FILES)) {
						_pacman_log(PM_LOG_DEBUG, _("loading FILES info for '%s'"), local->name);
						_pacman_db_read(db, INFRQ_FILES, local);
					}
					oldpkg->backup = _pacman_list_strdup(local->backup);
					strncpy(oldpkg->name, local->name, PKG_NAME_LEN);
					strncpy(oldpkg->version, local->version, PKG_VERSION_LEN);
				}

				/* pre_upgrade scriptlet */
				if(info->scriptlet && !(trans->flags & PM_TRANS_FLAG_NOSCRIPTLET)) {
					_pacman_runscriptlet(handle->root, info->data, "pre_upgrade", info->version, oldpkg ? oldpkg->version : NULL,
						trans);
				}

				if(oldpkg) {
					pmtrans_t *tr;
					_pacman_log(PM_LOG_FLOW1, _("removing old package first (%s-%s)"), oldpkg->name, oldpkg->version);
					tr = _pacman_trans_new();
					if(tr == NULL) {
						RET_ERR(PM_ERR_TRANS_ABORT, -1);
					}
					pmtrans_cbs_t null_cbs = { NULL };
					if(_pacman_trans_init(tr, PM_TRANS_TYPE_UPGRADE, trans->flags, null_cbs) == -1) {
						FREETRANS(tr);
						RET_ERR(PM_ERR_TRANS_ABORT, -1);
					}
					if(_pacman_remove_addtarget(tr, info->name) == -1) {
						FREETRANS(tr);
						RET_ERR(PM_ERR_TRANS_ABORT, -1);
					}
					/* copy the skiplist over */
					tr->skiplist = _pacman_list_strdup(trans->skiplist);
					if(_pacman_remove_commit(tr, NULL) == -1) {
						FREETRANS(tr);
						RET_ERR(PM_ERR_TRANS_ABORT, -1);
					}
					FREETRANS(tr);
				}
			} else {
				/* no previous package version is installed, so this is actually
				 * just an install.  */
				pmo_upgrade = 0;
			}
		}
		if(!pmo_upgrade) {
			EVENT(trans, PM_TRANS_EVT_ADD_START, info, NULL);
			cb_state = PM_TRANS_PROGRESS_ADD_START;
			_pacman_log(PM_LOG_FLOW1, _("adding package %s-%s"), info->name, info->version);
			if((what = _pacman_strdup(info->name)) == NULL) {
				return -1;
			}

			/* pre_install scriptlet */
			if(info->scriptlet && !(trans->flags & PM_TRANS_FLAG_NOSCRIPTLET)) {
				_pacman_runscriptlet(handle->root, info->data, "pre_install", info->version, NULL, trans);
			}
		} else {
			_pacman_log(PM_LOG_FLOW1, _("adding new package %s-%s"), info->name, info->version);
		}

		if(!(trans->flags & PM_TRANS_FLAG_DBONLY)) {
			_pacman_log(PM_LOG_FLOW1, _("extracting files"));

			/* Extract the package */
			if ((archive = archive_read_new ()) == NULL)
				RET_ERR(PM_ERR_LIBARCHIVE_ERROR, -1);

			archive_read_support_filter_all(archive);
			archive_read_support_format_all (archive);

			if (archive_read_open_filename(archive, info->data, PM_DEFAULT_BYTES_PER_BLOCK) != ARCHIVE_OK) {
				RET_ERR(PM_ERR_PKG_OPEN, -1);
			}

			/* save the cwd so we can restore it later */
			if(getcwd(cwd, PATH_MAX) == NULL) {
				_pacman_log(PM_LOG_ERROR, _("could not get current working directory"));
				/* in case of error, cwd content is undefined: so we set it to something */
				cwd[0] = 0;
			}

			/* libarchive requires this for extracting hard links */
			chdir(handle->root);

			for(i = 0; (archive_ret = archive_read_next_header (archive, &entry)) == ARCHIVE_OK; i++) {
				int nb = 0;
				int notouch = 0;
				char *hash_orig = NULL;
				char pathname[PATH_MAX];
				struct stat buf;

				STRNCPY(pathname, archive_entry_pathname (entry), PATH_MAX);

				if (info->usize != 0) {
					double percent = (double)archive_filter_bytes(archive, -1) / info->usize;
					PROGRESS(trans, cb_state, what, (int)(percent * 100), package_count, package_index);
				}

				if(!strcmp(pathname, ".PKGINFO") || !strcmp(pathname, ".FILELIST")) {
					archive_read_data_skip (archive);
					continue;
				}

				/*if(!strcmp(pathname, "._install") || !strcmp(pathname, ".INSTALL")) {
				*	 the install script goes inside the db
				*	snprintf(expath, PATH_MAX, "%s/%s-%s/install", db->path, info->name, info->version); */
				if(!strcmp(pathname, "._install") || !strcmp(pathname, ".INSTALL") ||
					!strcmp(pathname, ".CHANGELOG")) {
					if(!strcmp(pathname, ".CHANGELOG")) {
						/* the changelog goes inside the db */
						snprintf(expath, PATH_MAX, "%s/%s-%s/changelog", db->path,
							info->name, info->version);
					} else {
						/* the install script goes inside the db */
						snprintf(expath, PATH_MAX, "%s/%s-%s/install", db->path,
							info->name, info->version);
					}
				} else {
					/* build the new pathname relative to handle->root */
					snprintf(expath, PATH_MAX, "%s%s", handle->root, pathname);
					if(expath[strlen(expath)-1] == '/') {
						expath[strlen(expath)-1] = '\0';
					}
				}

				/* if a file is in NoExtract then we never extract it.
				 *
				 * eg, /home/httpd/html/index.html may be removed so index.php
				 * could be used.
				 */
				if(_pacman_list_is_strin(pathname, handle->noextract)) {
					pacman_logaction(_("notice: %s is in NoExtract -- skipping extraction"), pathname);
					archive_read_data_skip (archive);
					continue;
				}

				if(!lstat(expath, &buf)) {
					/* file already exists */
					if(S_ISLNK(buf.st_mode)) {
						continue;
					} else if(!S_ISDIR(buf.st_mode)) {
						if(_pacman_list_is_strin(pathname, handle->noupgrade)) {
							notouch = 1;
						} else {
							if(!pmo_upgrade || oldpkg == NULL) {
								nb = _pacman_list_is_strin(pathname, info->backup);
							} else {
								/* op == PM_TRANS_TYPE_UPGRADE */
								hash_orig = _pacman_needbackup(pathname, oldpkg->backup);
								if(hash_orig != NULL) {
									nb = 1;
								}
							}
						}
					}
				}

				if(nb) {
					char *temp;
					char *md5_local, *md5_pkg;
					char *sha1_local, *sha1_pkg;
					int fd;

					/* extract the package's version to a temporary file and md5 it */
					temp = strdup("/tmp/pacman_XXXXXX");
					fd = mkstemp(temp);

					archive_entry_set_pathname (entry, temp);

					if(archive_read_extract (archive, entry, ARCHIVE_EXTRACT_FLAGS) != ARCHIVE_OK) {
						_pacman_log(PM_LOG_ERROR, _("could not extract %s (%s)"), pathname, strerror(errno));
						pacman_logaction(_("could not extract %s (%s)"), pathname, strerror(errno));
						errors++;
						unlink(temp);
						FREE(temp);
						FREE(hash_orig);
						close(fd);
						continue;
					}
					md5_local = _pacman_MDFile(expath);
					md5_pkg = _pacman_MDFile(temp);
					sha1_local = _pacman_SHAFile(expath);
					sha1_pkg = _pacman_SHAFile(temp);
					/* append the new md5 or sha1 hash to it's respective entry in info->backup
					 * (it will be the new orginal)
					 */
					for(lp = info->backup; lp; lp = lp->next) {
						char *fn;
						char *file = lp->data;

						if(!file) continue;
						if(!strcmp(file, pathname)) {
							if (info->sha1sum[0] != '\0') {
							/* 32 for the hash, 1 for the terminating NULL, and 1 for the tab delimiter */
							if((fn = (char *)malloc(strlen(file)+34)) == NULL) {
								RET_ERR(PM_ERR_MEMORY, -1);
							}
							sprintf(fn, "%s\t%s", file, md5_pkg);
							FREE(file);
							lp->data = fn;
						    } else {
							/* 41 for the hash, 1 for the terminating NULL, and 1 for the tab delimiter */
							if((fn = (char *)malloc(strlen(file)+43)) == NULL) {
								RET_ERR(PM_ERR_MEMORY, -1);
							}
							sprintf(fn, "%s\t%s", file, sha1_pkg);
							FREE(file);
							lp->data = fn;
						    }
						}
					}

					if (info->sha1sum[0] != '\0') {
					_pacman_log(PM_LOG_DEBUG, _("checking md5 hashes for %s"), pathname);
					_pacman_log(PM_LOG_DEBUG, _("current:  %s"), md5_local);
					_pacman_log(PM_LOG_DEBUG, _("new:      %s"), md5_pkg);
					} else {
                                        _pacman_log(PM_LOG_DEBUG, _("checking sha1 hashes for %s"), pathname);
					_pacman_log(PM_LOG_DEBUG, _("current:  %s"), sha1_local);
                                        _pacman_log(PM_LOG_DEBUG, _("new:      %s"), sha1_pkg);
					}
					if(hash_orig) {
						_pacman_log(PM_LOG_DEBUG, _("original: %s"), hash_orig);
					}

					if(!pmo_upgrade) {
						/* PM_ADD */

						/* if a file already exists with a different md5 or sha1 hash,
						 * then we rename it to a .pacorig extension and continue */
						if(strcmp(md5_local, md5_pkg) || strcmp(sha1_local, sha1_pkg)) {
							char newpath[PATH_MAX];
							snprintf(newpath, PATH_MAX, "%s.pacorig", expath);
							if(rename(expath, newpath)) {
								archive_entry_set_pathname (entry, expath);
								_pacman_log(PM_LOG_ERROR, _("could not rename %s (%s)"), pathname, strerror(errno));
								pacman_logaction(_("error: could not rename %s (%s)"), expath, strerror(errno));
							}
							if(_pacman_copyfile(temp, expath)) {
								archive_entry_set_pathname (entry, expath);
								_pacman_log(PM_LOG_ERROR, _("could not copy %s to %s (%s)"), temp, pathname, strerror(errno));
								pacman_logaction(_("error: could not copy %s to %s (%s)"), temp, expath, strerror(errno));
								errors++;
							} else {
								archive_entry_set_pathname (entry, expath);
								_pacman_log(PM_LOG_WARNING, _("%s saved as %s.pacorig"), pathname, pathname);
								pacman_logaction(_("warning: %s saved as %s"), expath, newpath);
							}
						}
					} else if(hash_orig != NULL) {
						/* PM_UPGRADE */
						int installnew = 0;

						/* the fun part */
						if(!strcmp(hash_orig, md5_local)|| !strcmp(hash_orig, sha1_local)) {
							if(!strcmp(md5_local, md5_pkg) || !strcmp(sha1_local, sha1_pkg)) {
								_pacman_log(PM_LOG_DEBUG, _("action: installing new file"));
								installnew = 1;
							} else {
								_pacman_log(PM_LOG_DEBUG, _("action: installing new file"));
								installnew = 1;
							}
						} else if(!strcmp(hash_orig, md5_pkg) || !strcmp(hash_orig, sha1_pkg)) {
							_pacman_log(PM_LOG_DEBUG, _("action: leaving existing file in place"));
						} else if(!strcmp(md5_local, md5_pkg) || !strcmp(sha1_local, sha1_pkg)) {
							_pacman_log(PM_LOG_DEBUG, _("action: installing new file"));
							installnew = 1;
						} else {
							char newpath[PATH_MAX];
							_pacman_log(PM_LOG_DEBUG, _("action: keeping current file and installing new one with .pacnew ending"));
							installnew = 0;
							snprintf(newpath, PATH_MAX, "%s.pacnew", expath);
							if(_pacman_copyfile(temp, newpath)) {
								_pacman_log(PM_LOG_ERROR, _("could not install %s as %s: %s"), expath, newpath, strerror(errno));
								pacman_logaction(_("error: could not install %s as %s: %s"), expath, newpath, strerror(errno));
							} else {
								_pacman_log(PM_LOG_WARNING, _("%s installed as %s"), expath, newpath);
								pacman_logaction(_("warning: %s installed as %s"), expath, newpath);
							}
						}

						if(installnew) {
							_pacman_log(PM_LOG_FLOW2, _("extracting %s"), pathname);
							if(_pacman_copyfile(temp, expath)) {
								_pacman_log(PM_LOG_ERROR, _("could not copy %s to %s (%s)"), temp, pathname, strerror(errno));
								errors++;
							}
						    archive_entry_set_pathname (entry, expath);
						}
					}

					FREE(md5_local);
					FREE(md5_pkg);
					FREE(sha1_local);
					FREE(sha1_pkg);
					FREE(hash_orig);
					unlink(temp);
					FREE(temp);
					close(fd);
				} else {
					if(!notouch) {
						_pacman_log(PM_LOG_FLOW2, _("extracting %s"), pathname);
					} else {
						_pacman_log(PM_LOG_FLOW2, _("%s is in NoUpgrade -- skipping"), pathname);
						strncat(expath, ".pacnew", PATH_MAX);
						_pacman_log(PM_LOG_WARNING, _("extracting %s as %s.pacnew"), pathname, pathname);
						pacman_logaction(_("warning: extracting %s%s as %s"), handle->root, pathname, expath);
						/*tar_skip_regfile(tar);*/
					}
					if(trans->flags & PM_TRANS_FLAG_FORCE) {
						/* if FORCE was used, then unlink() each file (whether it's there
						 * or not) before extracting.  this prevents the old "Text file busy"
						 * error that crops up if one tries to --force a glibc or pacman-g2
						 * upgrade.
						 */
						unlink(expath);
					}
					archive_entry_set_pathname (entry, expath);
					if(archive_read_extract (archive, entry, ARCHIVE_EXTRACT_FLAGS) != ARCHIVE_OK) {
						_pacman_log(PM_LOG_ERROR, _("could not extract %s (%s)"), expath, strerror(errno));
						pacman_logaction(_("error: could not extract %s (%s)"), expath, strerror(errno));
						errors++;
					}
					/* calculate an md5 or sha1 hash if this is in info->backup */
					for(lp = info->backup; lp; lp = lp->next) {
						char *fn, *md5, *sha1;
						char path[PATH_MAX];
						char *file = lp->data;

						if(!file) continue;
						if(!strcmp(file, pathname)) {
							_pacman_log(PM_LOG_DEBUG, _("appending backup entry"));
							snprintf(path, PATH_MAX, "%s%s", handle->root, file);
							if (info->sha1sum[0] != '\0') {
							    md5 = _pacman_MDFile(path);
							    /* 32 for the hash, 1 for the terminating NULL, and 1 for the tab delimiter */
							    if((fn = (char *)malloc(strlen(file)+34)) == NULL) {
										RET_ERR(PM_ERR_MEMORY, -1);
									}
							    sprintf(fn, "%s\t%s", file, md5);
							    FREE(md5);
							} else {
							    /* 41 for the hash, 1 for the terminating NULL, and 1 for the tab delimiter */
							    sha1 = _pacman_SHAFile(path);
							    if((fn = (char *)malloc(strlen(file)+43)) == NULL) {
										RET_ERR(PM_ERR_MEMORY, -1);
									}
							    sprintf(fn, "%s\t%s", file, sha1);
							    FREE(sha1);
							}
							FREE(file);
							lp->data = fn;
						}
					}
				}
			}
			if(archive_ret == ARCHIVE_FATAL) {
				errors++;
			}
			if(strlen(cwd)) {
				chdir(cwd);
			}
			archive_read_free(archive);

			if(errors) {
				ret = 1;
				_pacman_log(PM_LOG_WARNING, _("errors occurred while %s %s"),
					(pmo_upgrade ? _("upgrading") : _("installing")), info->name);
				pacman_logaction(_("errors occurred while %s %s"),
					(pmo_upgrade ? _("upgrading") : _("installing")), info->name);
			} else {
			PROGRESS(trans, cb_state, what, 100, package_count, package_index);
			}
		}

		/* Add the package to the database */
		t = time(NULL);

		/* Update the requiredby field by scanning the whole database
		 * looking for packages depending on the package to add */
		for(lp = _pacman_db_get_pkgcache(db); lp; lp = lp->next) {
			pmpkg_t *tmpp = lp->data;
			pmlist_t *tmppm = NULL;
			if(tmpp == NULL) {
				continue;
			}
			for(tmppm = tmpp->depends; tmppm; tmppm = tmppm->next) {
				pmdepend_t depend;
				if(_pacman_splitdep(tmppm->data, &depend)) {
					continue;
				}
				if(tmppm->data && (!strcmp(depend.name, info->name) || _pacman_list_is_strin(depend.name, info->provides))) {
					_pacman_log(PM_LOG_DEBUG, _("adding '%s' in requiredby field for '%s'"), tmpp->name, info->name);
					info->requiredby = _pacman_list_add(info->requiredby, strdup(tmpp->name));
				}
			}
		}

		/* make an install date (in UTC) */
		STRNCPY(info->installdate, asctime(gmtime(&t)), sizeof(info->installdate));
		/* remove the extra line feed appended by asctime() */
		info->installdate[strlen(info->installdate)-1] = 0;

		_pacman_log(PM_LOG_FLOW1, _("updating database"));
		_pacman_log(PM_LOG_FLOW2, _("adding database entry '%s'"), info->name);
		if(_pacman_db_write(db, info, INFRQ_ALL)) {
			_pacman_log(PM_LOG_ERROR, _("could not update database entry %s-%s"),
			          info->name, info->version);
			pacman_logaction(NULL, _("error updating database for %s-%s!"), info->name, info->version);
			RET_ERR(PM_ERR_DB_WRITE, -1);
		}
		if(_pacman_db_add_pkgincache(db, info) == -1) {
			_pacman_log(PM_LOG_ERROR, _("could not add entry '%s' in cache"), info->name);
		}

		/* update dependency packages' REQUIREDBY fields */
		if(info->depends) {
			_pacman_log(PM_LOG_FLOW2, _("updating dependency packages 'requiredby' fields"));
		}
		for(lp = info->depends; lp; lp = lp->next) {
			pmpkg_t *depinfo;
			pmdepend_t depend;
			if(_pacman_splitdep(lp->data, &depend)) {
				continue;
			}
			depinfo = _pacman_db_get_pkgfromcache(db, depend.name);
			if(depinfo == NULL) {
				/* look for a provides package */
				pmlist_t *provides = _pacman_db_whatprovides(db, depend.name);
				if(provides) {
					/* TODO: should check _all_ packages listed in provides, not just
					 *       the first one.
					 */
					/* use the first one */
					depinfo = _pacman_db_get_pkgfromcache(db, ((pmpkg_t *)provides->data)->name);
					FREELISTPTR(provides);
				}
				if(depinfo == NULL) {
					_pacman_log(PM_LOG_ERROR, _("could not find dependency '%s'"), depend.name);
					/* wtf */
					continue;
				}
			}
			_pacman_log(PM_LOG_DEBUG, _("adding '%s' in requiredby field for '%s'"), info->name, depinfo->name);
			depinfo->requiredby = _pacman_list_add(_pacman_pkg_getinfo(depinfo, PM_PKG_REQUIREDBY), strdup(info->name));
			if(_pacman_db_write(db, depinfo, INFRQ_DEPENDS)) {
				_pacman_log(PM_LOG_ERROR, _("could not update 'requiredby' database entry %s-%s"),
				          depinfo->name, depinfo->version);
			}
		}

		EVENT(trans, PM_TRANS_EVT_EXTRACT_DONE, NULL, NULL);
		FREE(what);

		/* run the post-install script if it exists  */
		if(info->scriptlet && !(trans->flags & PM_TRANS_FLAG_NOSCRIPTLET)) {
			/* must run ldconfig here because some scriptlets fail due to missing libs otherwise */
			_pacman_ldconfig(handle->root);
			snprintf(pm_install, PATH_MAX, "%s%s/%s/%s-%s/install", handle->root, handle->dbpath, db->treename, info->name, info->version);
			if(pmo_upgrade) {
				_pacman_runscriptlet(handle->root, pm_install, "post_upgrade", info->version, oldpkg ? oldpkg->version : NULL, trans);
			} else {
				_pacman_runscriptlet(handle->root, pm_install, "post_install", info->version, NULL, trans);
			}
		}

		EVENT(trans, (pmo_upgrade) ? PM_TRANS_EVT_UPGRADE_DONE : PM_TRANS_EVT_ADD_DONE, info, oldpkg);

		FREEPKG(oldpkg);
	}

	/* run ldconfig if it exists */
	if(handle->trans->state != STATE_INTERRUPTED) {
		_pacman_ldconfig(handle->root);
	}

	return(ret);
}

int _pacman_trans_commit(pmtrans_t *trans, pmlist_t **data)
{
	/* Sanity checks */
	ASSERT(trans != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->ops != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));
	ASSERT(trans->ops->commit != NULL, RET_ERR(PM_ERR_TRANS_NULL, -1));

	if(data!=NULL)
		*data = NULL;

	/* If there's nothing to do, return without complaining */
	if(trans->packages == NULL) {
		return(0);
	}

	_pacman_trans_set_state(trans, STATE_COMMITING);

	if(trans->ops->commit(trans, data) == -1) {
		/* pm_errno is set by trans->ops->commit() */
		_pacman_trans_set_state(trans, STATE_PREPARED);
		return(-1);
	}

	_pacman_trans_set_state(trans, STATE_COMMITED);

	return(0);
}

/* vim: set ts=2 sw=2 noet: */

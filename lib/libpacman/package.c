/*
 *  package.c
 *
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2005, 2006 by Christian Hamar <krics@linuxforum.hu>
 *  Copyright (c) 2005, 2006. 2007 by Miklos Vajna <vmiklos@frugalware.org>
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
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include <sys/utsname.h>
/* pacman-g2 */
#include "log.h"
#include "util.h"
#include "error.h"
#include "list.h"
#include "db.h"
#include "handle.h"
#include "cache.h"
#include "package.h"
#include "pacman.h"

pmpkg_t *_pacman_pkg_new(const char *name, const char *version)
{
	pmpkg_t* pkg = NULL;

	if((pkg = (pmpkg_t *)malloc(sizeof(pmpkg_t))) == NULL) {
		RET_ERR(PM_ERR_MEMORY, (pmpkg_t *)-1);
	}

	if(name && name[0] != 0) {
		STRNCPY(pkg->name, name, PKG_NAME_LEN);
	} else {
		pkg->name[0]        = '\0';
	}
	if(version && version[0] != 0) {
		STRNCPY(pkg->version, version, PKG_VERSION_LEN);
	} else {
		pkg->version[0]     = '\0';
	}
	pkg->desc[0]        = '\0';
	pkg->url[0]         = '\0';
	pkg->license        = NULL;
	pkg->desc_localized = NULL;
	pkg->builddate[0]   = '\0';
	pkg->buildtype[0]   = '\0';
	pkg->installdate[0] = '\0';
	pkg->packager[0]    = '\0';
	pkg->md5sum[0]      = '\0';
	pkg->sha1sum[0]     = '\0';
	pkg->arch[0]        = '\0';
	pkg->size           = 0;
	pkg->usize          = 0;
	pkg->scriptlet      = 0;
	pkg->force          = 0;
	pkg->stick          = 0;
	pkg->reason         = PM_PKG_REASON_EXPLICIT;
	pkg->requiredby     = NULL;
	pkg->conflicts      = NULL;
	pkg->files          = NULL;
	pkg->backup         = NULL;
	pkg->depends        = NULL;
	pkg->removes        = NULL;
	pkg->groups         = NULL;
	pkg->provides       = NULL;
	pkg->replaces       = NULL;
	/* internal */
	pkg->origin         = 0;
	pkg->data           = NULL;
	pkg->infolevel      = 0;

	return(pkg);
}

pmpkg_t *_pacman_pkg_dup(pmpkg_t *pkg)
{
	pmpkg_t* newpkg = _pacman_malloc(sizeof(pmpkg_t));

	if(newpkg == NULL) {
		return(NULL);
	}

	STRNCPY(newpkg->name, pkg->name, PKG_NAME_LEN);
	STRNCPY(newpkg->version, pkg->version, PKG_VERSION_LEN);
	STRNCPY(newpkg->desc, pkg->desc, PKG_DESC_LEN);
	STRNCPY(newpkg->url, pkg->url, PKG_URL_LEN);
	STRNCPY(newpkg->builddate, pkg->builddate, PKG_DATE_LEN);
	STRNCPY(newpkg->buildtype, pkg->buildtype, PKG_DATE_LEN);
	STRNCPY(newpkg->installdate, pkg->installdate, PKG_DATE_LEN);
	STRNCPY(newpkg->packager, pkg->packager, PKG_PACKAGER_LEN);
	STRNCPY(newpkg->md5sum, pkg->md5sum, PKG_MD5SUM_LEN);
	STRNCPY(newpkg->sha1sum, pkg->sha1sum, PKG_SHA1SUM_LEN);
	STRNCPY(newpkg->arch, pkg->arch, PKG_ARCH_LEN);
	newpkg->size       = pkg->size;
	newpkg->usize      = pkg->usize;
	newpkg->force      = pkg->force;
	newpkg->stick      = pkg->stick;
	newpkg->scriptlet  = pkg->scriptlet;
	newpkg->reason     = pkg->reason;
	newpkg->license    = _pacman_list_strdup(pkg->license);
	newpkg->desc_localized = _pacman_list_strdup(pkg->desc_localized);
	newpkg->requiredby = _pacman_list_strdup(pkg->requiredby);
	newpkg->conflicts  = _pacman_list_strdup(pkg->conflicts);
	newpkg->files      = _pacman_list_strdup(pkg->files);
	newpkg->backup     = _pacman_list_strdup(pkg->backup);
	newpkg->depends    = _pacman_list_strdup(pkg->depends);
	newpkg->removes    = _pacman_list_strdup(pkg->removes);
	newpkg->groups     = _pacman_list_strdup(pkg->groups);
	newpkg->provides   = _pacman_list_strdup(pkg->provides);
	newpkg->replaces   = _pacman_list_strdup(pkg->replaces);
	/* internal */
	newpkg->origin     = pkg->origin;
	newpkg->data = (newpkg->origin == PKG_FROM_FILE) ? strdup(pkg->data) : pkg->data;
	newpkg->infolevel  = pkg->infolevel;

	return(newpkg);
}

void _pacman_pkg_free(void *data)
{
	pmpkg_t *pkg = data;

	if(pkg == NULL) {
		return;
	}

	FREELIST(pkg->license);
	FREELIST(pkg->desc_localized);
	FREELIST(pkg->files);
	FREELIST(pkg->backup);
	FREELIST(pkg->depends);
	FREELIST(pkg->removes);
	FREELIST(pkg->conflicts);
	FREELIST(pkg->requiredby);
	FREELIST(pkg->groups);
	FREELIST(pkg->provides);
	FREELIST(pkg->replaces);
	if(pkg->origin == PKG_FROM_FILE) {
		FREE(pkg->data);
	}
	free(pkg);

	return;
}

/* Helper function for comparing packages
 */
int _pacman_pkg_cmp(const void *p1, const void *p2)
{
	return(strcmp(((pmpkg_t *)p1)->name, ((pmpkg_t *)p2)->name));
}

/* Parses the package description file for the current package
 *
 * Returns: 0 on success, 1 on error
 *
 */
static int parse_descfile(char *descfile, pmpkg_t *info, int output)
{
	FILE* fp = NULL;
	char line[PATH_MAX];
	char* ptr = NULL;
	char* key = NULL;
	int linenum = 0;

	if((fp = fopen(descfile, "r")) == NULL) {
		_pacman_log(PM_LOG_ERROR, _("could not open file %s"), descfile);
		return(-1);
	}

	while(!feof(fp)) {
		fgets(line, PATH_MAX, fp);
		linenum++;
		_pacman_strtrim(line);
		if(strlen(line) == 0 || line[0] == '#') {
			continue;
		}
		if(output) {
			_pacman_log(PM_LOG_DEBUG, "%s", line);
		}
		ptr = line;
		key = strsep(&ptr, "=");
		if(key == NULL || ptr == NULL) {
			_pacman_log(PM_LOG_DEBUG, _("%s: syntax error in description file line %d"),
				info->name[0] != '\0' ? info->name : "error", linenum);
		} else {
			_pacman_strtrim(key);
			key = _pacman_strtoupper(key);
			_pacman_strtrim(ptr);
			if(!strcmp(key, "PKGNAME")) {
				STRNCPY(info->name, ptr, sizeof(info->name));
			} else if(!strcmp(key, "PKGVER")) {
				STRNCPY(info->version, ptr, sizeof(info->version));
			} else if(!strcmp(key, "PKGDESC")) {
				info->desc_localized = _pacman_list_add(info->desc_localized, strdup(ptr));
				if(_pacman_list_count(info->desc_localized) == 1) {
					STRNCPY(info->desc, ptr, sizeof(info->desc));
				} else if (!strncmp(ptr, handle->language, strlen(handle->language))) {
					STRNCPY(info->desc, ptr+strlen(handle->language)+1, sizeof(info->desc));
				}
			} else if(!strcmp(key, "GROUP")) {
				info->groups = _pacman_list_add(info->groups, strdup(ptr));
			} else if(!strcmp(key, "URL")) {
				STRNCPY(info->url, ptr, sizeof(info->url));
			} else if(!strcmp(key, "LICENSE")) {
				info->license = _pacman_list_add(info->license, strdup(ptr));
			} else if(!strcmp(key, "BUILDDATE")) {
				STRNCPY(info->builddate, ptr, sizeof(info->builddate));
			} else if(!strcmp(key, "BUILDTYPE")) {
				STRNCPY(info->buildtype, ptr, sizeof(info->buildtype));
			} else if(!strcmp(key, "INSTALLDATE")) {
				STRNCPY(info->installdate, ptr, sizeof(info->installdate));
			} else if(!strcmp(key, "PACKAGER")) {
				STRNCPY(info->packager, ptr, sizeof(info->packager));
			} else if(!strcmp(key, "ARCH")) {
				STRNCPY(info->arch, ptr, sizeof(info->arch));
			} else if(!strcmp(key, "SIZE")) {
				char tmp[32];
				STRNCPY(tmp, ptr, sizeof(tmp));
				info->size = atol(tmp);
			} else if(!strcmp(key, "USIZE")) {
				char tmp[32];
				STRNCPY(tmp, ptr, sizeof(tmp));
				info->usize = atol(tmp);
			} else if(!strcmp(key, "DEPEND")) {
				info->depends = _pacman_list_add(info->depends, strdup(ptr));
			} else if(!strcmp(key, "REMOVE")) {
				info->removes = _pacman_list_add(info->removes, strdup(ptr));
			} else if(!strcmp(key, "CONFLICT")) {
				info->conflicts = _pacman_list_add(info->conflicts, strdup(ptr));
			} else if(!strcmp(key, "REPLACES")) {
				info->replaces = _pacman_list_add(info->replaces, strdup(ptr));
			} else if(!strcmp(key, "PROVIDES")) {
				info->provides = _pacman_list_add(info->provides, strdup(ptr));
			} else if(!strcmp(key, "BACKUP")) {
				info->backup = _pacman_list_add(info->backup, strdup(ptr));
			} else {
				_pacman_log(PM_LOG_DEBUG, _("%s: syntax error in description file line %d"),
					info->name[0] != '\0' ? info->name : "error", linenum);
			}
		}
		line[0] = '\0';
	}
	fclose(fp);

	return(0);
}

pmpkg_t *_pacman_pkg_load(const char *pkgfile)
{
	char *expath;
	int i, ret;
	int config = 0;
	int filelist = 0;
	int scriptcheck = 0;
	register struct archive *archive;
	struct archive_entry *entry;
	struct utsname name;
	pmpkg_t *info = NULL;

	if(pkgfile == NULL || strlen(pkgfile) == 0) {
		RET_ERR(PM_ERR_WRONG_ARGS, NULL);
	}

	if ((archive = archive_read_new ()) == NULL)
		RET_ERR(PM_ERR_LIBARCHIVE_ERROR, NULL);

	archive_read_support_compression_all (archive);
	archive_read_support_format_all (archive);

	if ((ret = archive_read_open_file (archive, pkgfile, PM_DEFAULT_BYTES_PER_BLOCK)) != ARCHIVE_OK)
		RET_ERR(PM_ERR_PKG_OPEN, NULL);

	info = _pacman_pkg_new(NULL, NULL);
	if(info == NULL) {
		archive_read_finish (archive);
		RET_ERR(PM_ERR_MEMORY, NULL);
	}

	for(i = 0; (ret = archive_read_next_header (archive, &entry)) == ARCHIVE_OK; i++) {
		if(config && filelist && scriptcheck) {
			/* we have everything we need */
			break;
		}
		if(!strcmp(archive_entry_pathname (entry), ".PKGINFO")) {
			char *descfile;
			int fd, parse_success;

			/* extract this file into /tmp. it has info for us */
			descfile = strdup("/tmp/pacman_XXXXXX");
			fd = mkstemp(descfile);
			archive_read_data_into_fd (archive, fd);
			close(fd);
			/* parse the info file */
			parse_success = parse_descfile(descfile, info, 0);
			unlink(descfile);
			FREE(descfile);

			if(parse_success == -1) {
				_pacman_log(PM_LOG_ERROR, _("could not parse the package description file"));
				pm_errno = PM_ERR_PKG_INVALID;
				goto error;
			}
			if(!strlen(info->name)) {
				_pacman_log(PM_LOG_ERROR, _("missing package name in %s"), pkgfile);
				pm_errno = PM_ERR_PKG_INVALID;
				goto error;
			}
			if(!strlen(info->version)) {
				_pacman_log(PM_LOG_ERROR, _("missing package version in %s"), pkgfile);
				pm_errno = PM_ERR_PKG_INVALID;
				goto error;
			}
			if(handle->trans && !(handle->trans->flags & PM_TRANS_FLAG_NOARCH)) {
				if(!strlen(info->arch)) {
					_pacman_log(PM_LOG_ERROR, _("missing package architecture in %s"), pkgfile);
					pm_errno = PM_ERR_PKG_INVALID;
					goto error;
				}

				uname (&name);
				if(strncmp(name.machine, info->arch, strlen(info->arch))) {
					_pacman_log(PM_LOG_ERROR, _("wrong package architecture in %s"), pkgfile);
					pm_errno = PM_ERR_WRONG_ARCH;
					goto error;
				}
			}
			config = 1;
			continue;
		} else if(!strcmp(archive_entry_pathname (entry), "._install") || !strcmp(archive_entry_pathname (entry),  ".INSTALL")) {
			info->scriptlet = 1;
			scriptcheck = 1;
		} else if(!strcmp(archive_entry_pathname (entry), ".FILELIST")) {
			/* Build info->files from the filelist */
			FILE *fp;
			char *fn;
			char *str;
			int fd;

			if((str = (char *)malloc(PATH_MAX)) == NULL) {
				RET_ERR(PM_ERR_MEMORY, (pmpkg_t *)-1);
			}
			fn = strdup("/tmp/pacman_XXXXXX");
			fd = mkstemp(fn);
			archive_read_data_into_fd (archive,fd);
			close(fd);
			fp = fopen(fn, "r");
			while(!feof(fp)) {
				if(fgets(str, PATH_MAX, fp) == NULL) {
					continue;
				}
				_pacman_strtrim(str);
				info->files = _pacman_list_add(info->files, strdup(str));
			}
			FREE(str);
			fclose(fp);
			if(unlink(fn)) {
				_pacman_log(PM_LOG_WARNING, _("could not remove tempfile %s"), fn);
			}
			FREE(fn);
			filelist = 1;
			continue;
		} else {
			scriptcheck = 1;
			if(!filelist) {
				/* no .FILELIST present in this package..  build the filelist the */
				/* old-fashioned way, one at a time */
				expath = strdup(archive_entry_pathname (entry));
				info->files = _pacman_list_add(info->files, expath);
			}
		}

		if(archive_read_data_skip (archive)) {
			_pacman_log(PM_LOG_ERROR, _("bad package file in %s"), pkgfile);
			goto error;
		}
		expath = NULL;
	}
	archive_read_finish (archive);

	if(!config) {
		_pacman_log(PM_LOG_ERROR, _("missing package info file in %s"), pkgfile);
		goto error;
	}

	/* internal */
	info->origin = PKG_FROM_FILE;
	info->data = strdup(pkgfile);
	info->infolevel = 0xFF;

	return(info);

error:
	FREEPKG(info);
	if(!ret) {
		archive_read_finish (archive);
	}
	pm_errno = PM_ERR_PKG_CORRUPTED;

	return(NULL);
}

/* Test for existence of a package in a pmlist_t*
 * of pmpkg_t*
 */
pmpkg_t *_pacman_pkg_isin(const char *needle, pmlist_t *haystack)
{
	pmlist_t *lp;

	if(needle == NULL || haystack == NULL) {
		return(NULL);
	}

	for(lp = haystack; lp; lp = lp->next) {
		pmpkg_t *info = lp->data;

		if(info && !strcmp(info->name, needle)) {
			return(lp->data);
		}
	}
	return(NULL);
}

int _pacman_pkg_splitname(char *target, char *name, char *version, int witharch)
{
	char tmp[PKG_FULLNAME_LEN+7];
	char *p, *q;

	if(target == NULL) {
		return(-1);
	}

	/* trim path name (if any) */
	if((p = strrchr(target, '/')) == NULL) {
		p = target;
	} else {
		p++;
	}
	STRNCPY(tmp, p, PKG_FULLNAME_LEN+7);
	/* trim file extension (if any) */
	if((p = strstr(tmp, PM_EXT_PKG))) {
		*p = 0;
	}
	if(witharch) {
		/* trim architecture */
		if((p = strrchr(tmp, '-'))) {
			*p = 0;
		}
	}

	p = tmp + strlen(tmp);

	for(q = --p; *q && *q != '-'; q--);
	if(*q != '-' || q == tmp) {
		return(-1);
	}
	for(p = --q; *p && *p != '-'; p--);
	if(*p != '-' || p == tmp) {
		return(-1);
	}
	if(version) {
		STRNCPY(version, p+1, PKG_VERSION_LEN);
	}
	*p = 0;

	if(name) {
		STRNCPY(name, tmp, PKG_NAME_LEN);
	}

	return(0);
}

void *_pacman_pkg_getinfo(pmpkg_t *pkg, unsigned char parm)
{
	void *data = NULL;

	/* Update the cache package entry if needed */
	if(pkg->origin == PKG_FROM_CACHE) {
		switch(parm) {
			/* Desc entry */
			case PM_PKG_DESC:
			case PM_PKG_GROUPS:
			case PM_PKG_URL:
			case PM_PKG_LICENSE:
			case PM_PKG_ARCH:
			case PM_PKG_BUILDDATE:
			case PM_PKG_INSTALLDATE:
			case PM_PKG_PACKAGER:
			case PM_PKG_SIZE:
			case PM_PKG_USIZE:
			case PM_PKG_REASON:
			case PM_PKG_MD5SUM:
			case PM_PKG_SHA1SUM:
			case PM_PKG_REPLACES:
			case PM_PKG_FORCE:
				if(!(pkg->infolevel & INFRQ_DESC)) {
					_pacman_log(PM_LOG_DEBUG, _("loading DESC info for '%s'"), pkg->name);
					_pacman_db_read(pkg->data, INFRQ_DESC, pkg);
				}
			break;
			/* Depends entry */
			case PM_PKG_DEPENDS:
			case PM_PKG_REQUIREDBY:
			case PM_PKG_CONFLICTS:
			case PM_PKG_PROVIDES:
				if(!(pkg->infolevel & INFRQ_DEPENDS)) {
					_pacman_log(PM_LOG_DEBUG, "loading DEPENDS info for '%s'", pkg->name);
					_pacman_db_read(pkg->data, INFRQ_DEPENDS, pkg);
				}
			break;
			/* Files entry */
			case PM_PKG_FILES:
			case PM_PKG_BACKUP:
				if(pkg->data == handle->db_local && !(pkg->infolevel & INFRQ_FILES)) {
					_pacman_log(PM_LOG_DEBUG, _("loading FILES info for '%s'"), pkg->name);
					_pacman_db_read(pkg->data, INFRQ_FILES, pkg);
				}
			break;
			/* Scriptlet */
			case PM_PKG_SCRIPLET:
				if(pkg->data == handle->db_local && !(pkg->infolevel & INFRQ_SCRIPLET)) {
					_pacman_log(PM_LOG_DEBUG, _("loading SCRIPLET info for '%s'"), pkg->name);
					_pacman_db_read(pkg->data, INFRQ_SCRIPLET, pkg);
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
		case PM_PKG_BUILDTYPE:   data = pkg->buildtype; break;
		case PM_PKG_INSTALLDATE: data = pkg->installdate; break;
		case PM_PKG_PACKAGER:    data = pkg->packager; break;
		case PM_PKG_SIZE:        data = (void *)(long)pkg->size; break;
		case PM_PKG_USIZE:       data = (void *)(long)pkg->usize; break;
		case PM_PKG_REASON:      data = (void *)(long)pkg->reason; break;
		case PM_PKG_LICENSE:     data = pkg->license; break;
		case PM_PKG_REPLACES:    data = pkg->replaces; break;
		case PM_PKG_FORCE:       data = (void *)(long)pkg->force; break;
		case PM_PKG_STICK:       data = (void *)(long)pkg->stick; break;
		case PM_PKG_MD5SUM:      data = pkg->md5sum; break;
		case PM_PKG_SHA1SUM:     data = pkg->sha1sum; break;
		case PM_PKG_DEPENDS:     data = pkg->depends; break;
		case PM_PKG_REMOVES:     data = pkg->removes; break;
		case PM_PKG_REQUIREDBY:  data = pkg->requiredby; break;
		case PM_PKG_PROVIDES:    data = pkg->provides; break;
		case PM_PKG_CONFLICTS:   data = pkg->conflicts; break;
		case PM_PKG_FILES:       data = pkg->files; break;
		case PM_PKG_BACKUP:      data = pkg->backup; break;
		case PM_PKG_SCRIPLET:    data = (void *)(long)pkg->scriptlet; break;
		case PM_PKG_DATA:        data = pkg->data; break;
		default:
			data = NULL;
		break;
	}

	return(data);
}

pmlist_t *_pacman_pkg_getowners(char *filename)
{
	struct stat buf;
	int gotcha = 0;
	char rpath[PATH_MAX];
	pmlist_t *lp, *ret = NULL;

	if(stat(filename, &buf) == -1 || realpath(filename, rpath) == NULL) {
		RET_ERR(PM_ERR_PKG_OPEN, NULL);
	}

	if(S_ISDIR(buf.st_mode)) {
		/* this is a directory and the db has a / suffix for dirs - add it here so
		 * that we'll find dirs, too */
		rpath[strlen(rpath)+1] = '\0';
		rpath[strlen(rpath)] = '/';
	}

	for(lp = _pacman_db_get_pkgcache(handle->db_local); lp; lp = lp->next) {
		pmpkg_t *info;
		pmlist_t *i;

		info = lp->data;

		for(i = _pacman_pkg_getinfo(info, PM_PKG_FILES); i; i = i->next) {
			char path[PATH_MAX];

			snprintf(path, PATH_MAX, "%s%s", handle->root, (char *)i->data);
			if(!strcmp(path, rpath)) {
				ret = _pacman_list_add(ret, info);
				if(rpath[strlen(rpath)-1] != '/') {
					/* we are searching for a file and multiple packages won't contain
					 * the same file */
					return(ret);
				}
				gotcha = 1;
			}
		}
	}
	if(!gotcha) {
		RET_ERR(PM_ERR_NO_OWNER, NULL);
	}

	return(ret);
}

void _pacman_pkg_filename(char *str, size_t size, const pmpkg_t *pkg)
{
	snprintf(str, size, "%s-%s-%s%s",
			pkg->name, pkg->version, pkg->arch, PM_EXT_PKG);
}

/* vim: set ts=2 sw=2 noet: */

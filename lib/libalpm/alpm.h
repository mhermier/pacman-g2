/*
 * alpm.h
 * 
 *  Copyright (c) 2005 by Judd Vinet <jvinet@zeroflux.org>
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
#ifndef _ALPM_H
#define _ALPM_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Arch Linux Package Management library
 */

#define PM_ROOT     "/"
#define PM_DBPATH   "var/lib/pacman"
#define PM_CACHEDIR "var/cache/pacman/pkg"
#define PM_LOCK     "/tmp/pacman.lck"


#define PM_EXT_PKG ".fpm"
#define PM_EXT_DB  ".fdb"

/* 
 * Structures (opaque)
 */

typedef struct __pmlist_t PM_LIST;
typedef struct __pmdb_t PM_DB;
typedef struct __pmpkg_t PM_PKG;
typedef struct __pmgrp_t PM_GRP;
typedef struct __pmsyncpkg_t PM_SYNCPKG;
typedef struct __pmtrans_t PM_TRANS;
typedef struct __pmdepmissing_t PM_DEPMISS;
typedef struct __pmconflict_t PM_CONFLICT;

/*
 * Library
 */

int alpm_initialize(char *root);
int alpm_release(void);

/*
 * Logging facilities
 */

/* Levels */
#define PM_LOG_DEBUG    0x01
#define PM_LOG_ERROR    0x02
#define PM_LOG_WARNING  0x04
#define PM_LOG_FLOW1    0x08
#define PM_LOG_FLOW2    0x10
#define PM_LOG_FUNCTION 0x20

/* Log callback */
typedef void (*alpm_cb_log)(unsigned short, char *);

int alpm_logaction(char *fmt, ...);

/*
 * Options
 */

/* Parameters */
enum {
	PM_OPT_LOGCB = 1,
	PM_OPT_LOGMASK,
	PM_OPT_USESYSLOG,
	PM_OPT_ROOT,
	PM_OPT_DBPATH,
	PM_OPT_CACHEDIR,
	PM_OPT_LOGFILE,
	PM_OPT_LOCALDB,
	PM_OPT_SYNCDB,
	PM_OPT_NOUPGRADE,
	PM_OPT_NOEXTRACT,
	PM_OPT_IGNOREPKG,
	PM_OPT_UPGRADEDELAY,
	/* Download */
	PM_OPT_PROXYHOST,
	PM_OPT_PROXYPORT,
	PM_OPT_XFERCOMMAND,
	PM_OPT_NOPASSIVEFTP,
	PM_OPT_DLCB,
	PM_OPT_DLFNM,
	PM_OPT_DLOFFSET,
	PM_OPT_DLT0,
	PM_OPT_DLT,
	PM_OPT_DLRATE,
	PM_OPT_DLXFERED1,
	PM_OPT_DLETA_H,
	PM_OPT_DLETA_M,
	PM_OPT_DLETA_S,
	/* End of download */
	PM_OPT_HOLDPKG,
	PM_OPT_CHOMP
};

int alpm_set_option(unsigned char parm, unsigned long data);
int alpm_get_option(unsigned char parm, long *data);

/*
 * Databases
 */

/* Info parameters */
enum {
	PM_DB_TREENAME = 1,
	PM_DB_FIRSTSERVER
};

/* Database registration callback */
typedef void (*alpm_cb_db_register)(char *, PM_DB *);

PM_DB *alpm_db_register(char *treename);
int alpm_db_unregister(PM_DB *db);

void *alpm_db_getinfo(PM_DB *db, unsigned char parm);
int alpm_db_setserver(PM_DB *db, char *url);

int alpm_db_update(int level, PM_DB *db);

PM_PKG *alpm_db_readpkg(PM_DB *db, char *name);
PM_LIST *alpm_db_getpkgcache(PM_DB *db);
PM_LIST *alpm_db_whatprovides(PM_DB *db, char *name);

PM_GRP *alpm_db_readgrp(PM_DB *db, char *name);
PM_LIST *alpm_db_getgrpcache(PM_DB *db);

/*
 * Packages
 */

/* Info parameters */
enum {
	/* Desc entry */
	PM_PKG_NAME = 1,
	PM_PKG_VERSION,
	PM_PKG_DESC,
	PM_PKG_GROUPS,
	PM_PKG_URL,
	PM_PKG_LICENSE,
	PM_PKG_ARCH,
	PM_PKG_BUILDDATE,
	PM_PKG_BUILDTYPE,
	PM_PKG_INSTALLDATE,
	PM_PKG_PACKAGER,
	PM_PKG_SIZE,
	PM_PKG_USIZE,
	PM_PKG_REASON,
	PM_PKG_MD5SUM, /* Sync DB only */
	PM_PKG_SHA1SUM, /* Sync DB only */
	/* Depends entry */
	PM_PKG_DEPENDS,
	PM_PKG_REMOVES,
	PM_PKG_REQUIREDBY,
	PM_PKG_CONFLICTS,
	PM_PKG_PROVIDES,
	PM_PKG_REPLACES, /* Sync DB only */
	/* Files entry */
	PM_PKG_FILES,
	PM_PKG_BACKUP,
	/* Sciplet */
	PM_PKG_SCRIPLET,
	/* Misc */
	PM_PKG_DATA
};

/* reasons -- ie, why the package was installed */
#define PM_PKG_REASON_EXPLICIT  0  /* explicitly requested by the user */
#define PM_PKG_REASON_DEPEND    1  /* installed as a dependency for another package */

/* package name formats */
#define PM_PKG_WITHOUT_ARCH 0 /* pkgname-pkgver-pkgrel, used under PM_DBPATH */
#define PM_PKG_WITH_ARCH    1 /* ie, pkgname-pkgver-pkgrel-arch, used under PM_CACHEDIR */

void *alpm_pkg_getinfo(PM_PKG *pkg, unsigned char parm);
int alpm_pkg_load(char *filename, PM_PKG **pkg);
int alpm_pkg_free(PM_PKG *pkg);
int alpm_pkg_checkmd5sum(PM_PKG *pkg);
int alpm_pkg_checksha1sum(PM_PKG *pkg);
char *alpm_fetch_pkgurl(char *url);
int alpm_parse_config(char *file, alpm_cb_db_register callback);
int alpm_pkg_vercmp(const char *ver1, const char *ver2);

/*
 * Groups
 */

/* Info parameters */
enum {
	PM_GRP_NAME = 1,
	PM_GRP_PKGNAMES
};

void *alpm_grp_getinfo(PM_GRP *grp, unsigned char parm);

/*
 * Sync
 */

/* Types */
enum {
	PM_SYNC_TYPE_REPLACE = 1,
	PM_SYNC_TYPE_UPGRADE,
	PM_SYNC_TYPE_DEPEND
};
/* Info parameters */
enum {
	PM_SYNC_TYPE = 1,
	PM_SYNC_PKG,
	PM_SYNC_DATA
};

void *alpm_sync_getinfo(PM_SYNCPKG *sync, unsigned char parm);

/*
 * Transactions
 */

/* Types */
enum {
	PM_TRANS_TYPE_ADD = 1,
	PM_TRANS_TYPE_REMOVE,
	PM_TRANS_TYPE_UPGRADE,
	PM_TRANS_TYPE_SYNC
};

/* Flags */
#define PM_TRANS_FLAG_NODEPS  0x01
#define PM_TRANS_FLAG_FORCE   0x02
#define PM_TRANS_FLAG_NOSAVE  0x04
#define PM_TRANS_FLAG_FRESHEN 0x08
#define PM_TRANS_FLAG_CASCADE 0x10
#define PM_TRANS_FLAG_RECURSE 0x20
#define PM_TRANS_FLAG_DBONLY  0x40
#define PM_TRANS_FLAG_DEPENDSONLY 0x80
#define PM_TRANS_FLAG_ALLDEPS 0x100
#define PM_TRANS_FLAG_DOWNLOADONLY 0x200
#define PM_TRANS_FLAG_NOSCRIPTLET 0x400
#define PM_TRANS_FLAG_NOCONFLICTS 0x800
#define PM_TRANS_FLAG_PRINTURIS 0x1000

/* Transaction Events */
enum {
	PM_TRANS_EVT_CHECKDEPS_START = 1,
	PM_TRANS_EVT_CHECKDEPS_DONE,
	PM_TRANS_EVT_FILECONFLICTS_START,
	PM_TRANS_EVT_FILECONFLICTS_DONE,
	PM_TRANS_EVT_CLEANUP_START,
	PM_TRANS_EVT_CLEANUP_DONE,
	PM_TRANS_EVT_RESOLVEDEPS_START,
	PM_TRANS_EVT_RESOLVEDEPS_DONE,
	PM_TRANS_EVT_INTERCONFLICTS_START,
	PM_TRANS_EVT_INTERCONFLICTS_DONE,
	PM_TRANS_EVT_ADD_START,
	PM_TRANS_EVT_ADD_DONE,
	PM_TRANS_EVT_REMOVE_START,
	PM_TRANS_EVT_REMOVE_DONE,
	PM_TRANS_EVT_UPGRADE_START,
	PM_TRANS_EVT_UPGRADE_DONE,
	PM_TRANS_EVT_EXTRACT_DONE,
	PM_TRANS_EVT_INTEGRITY_START,
	PM_TRANS_EVT_INTEGRITY_DONE,
	PM_TRANS_EVT_SCRIPTLET_INFO,
	PM_TRANS_EVT_SCRIPTLET_START,
	PM_TRANS_EVT_SCRIPTLET_DONE,
	PM_TRANS_EVT_PRINTURI,
	PM_TRANS_EVT_RETRIEVE_START,
	PM_TRANS_EVT_RETRIEVE_LOCAL
};

/* Transaction Conversations (ie, questions) */
enum {
	PM_TRANS_CONV_INSTALL_IGNOREPKG = 0x01,
	PM_TRANS_CONV_REPLACE_PKG = 0x02,
	PM_TRANS_CONV_CONFLICT_PKG = 0x04,
	PM_TRANS_CONV_CORRUPTED_PKG = 0x08,
	PM_TRANS_CONV_LOCAL_NEWER = 0x10,
	PM_TRANS_CONV_LOCAL_UPTODATE = 0x20,
	PM_TRANS_CONV_REMOVE_HOLDPKG = 0x40
};

/* Transaction Progress */
enum {
	PM_TRANS_PROGRESS_ADD_START,
	PM_TRANS_PROGRESS_UPGRADE_START,
	PM_TRANS_PROGRESS_REMOVE_START
};

/* Transaction Event callback */
typedef void (*alpm_trans_cb_event)(unsigned char, void *, void *);

/* Transaction Conversation callback */
typedef void (*alpm_trans_cb_conv)(unsigned char, void *, void *, void *, int *);

/* Transaction Progress callback */
typedef void (*alpm_trans_cb_progress)(unsigned char, char *, int, int, int);

/* Info parameters */
enum {
	PM_TRANS_TYPE = 1,
	PM_TRANS_FLAGS,
	PM_TRANS_TARGETS,
	PM_TRANS_PACKAGES
};

void *alpm_trans_getinfo(unsigned char parm);
int alpm_trans_init(unsigned char type, unsigned int flags, alpm_trans_cb_event cb_event, alpm_trans_cb_conv conv, alpm_trans_cb_progress cb_progress);
int alpm_trans_sysupgrade(void);
int alpm_trans_addtarget(char *target);
int alpm_trans_prepare(PM_LIST **data);
int alpm_trans_commit(PM_LIST **data);
int alpm_trans_release(void);

/*
 * Dependencies and conflicts
 */

enum {
	PM_DEP_MOD_ANY = 1,
	PM_DEP_MOD_EQ,
	PM_DEP_MOD_GE,
	PM_DEP_MOD_LE
};
enum {
	PM_DEP_TYPE_DEPEND = 1,
	PM_DEP_TYPE_REQUIRED,
	PM_DEP_TYPE_CONFLICT
};
/* Info parameters */
enum {
	PM_DEP_TARGET = 1,
	PM_DEP_TYPE,
	PM_DEP_MOD,
	PM_DEP_NAME,
	PM_DEP_VERSION
};

void *alpm_dep_getinfo(PM_DEPMISS *miss, unsigned char parm);

/*
 * File conflicts
 */

enum {
	PM_CONFLICT_TYPE_TARGET = 1,
	PM_CONFLICT_TYPE_FILE
};
/* Info parameters */
enum {
	PM_CONFLICT_TARGET = 1,
	PM_CONFLICT_TYPE,
	PM_CONFLICT_FILE,
	PM_CONFLICT_CTARGET
};

void *alpm_conflict_getinfo(PM_CONFLICT *conflict, unsigned char parm);

/*
 * Helpers
 */
 
/* PM_LIST */
PM_LIST *alpm_list_first(PM_LIST *list);
PM_LIST *alpm_list_next(PM_LIST *entry);
void *alpm_list_getdata(PM_LIST *entry);
int alpm_list_free(PM_LIST *entry);
int alpm_list_count(PM_LIST *list);

/* md5sums */
char *alpm_get_md5sum(char *name);
char *alpm_get_sha1sum(char *name);

/*
 * Errors
 */

extern enum __pmerrno_t {
	PM_ERR_MEMORY = 1,
	PM_ERR_SYSTEM,
	PM_ERR_BADPERMS,
	PM_ERR_NOT_A_FILE,
	PM_ERR_WRONG_ARGS,
	/* Interface */
	PM_ERR_HANDLE_NULL,
	PM_ERR_HANDLE_NOT_NULL,
	PM_ERR_HANDLE_LOCK,
	/* Databases */
	PM_ERR_DB_OPEN,
	PM_ERR_DB_CREATE,
	PM_ERR_DB_NULL,
	PM_ERR_DB_NOT_NULL,
	PM_ERR_DB_NOT_FOUND,
	PM_ERR_DB_WRITE,
	PM_ERR_DB_REMOVE,
	/* Servers */
	PM_ERR_SERVER_BAD_LOCATION,
	PM_ERR_SERVER_PROTOCOL_UNSUPPORTED,
	/* Configuration */
	PM_ERR_OPT_LOGFILE,
	PM_ERR_OPT_DBPATH,
	PM_ERR_OPT_LOCALDB,
	PM_ERR_OPT_SYNCDB,
	PM_ERR_OPT_USESYSLOG,
	/* Transactions */
	PM_ERR_TRANS_NOT_NULL,
	PM_ERR_TRANS_NULL,
	PM_ERR_TRANS_DUP_TARGET,
	PM_ERR_TRANS_NOT_INITIALIZED,
	PM_ERR_TRANS_NOT_PREPARED,
	PM_ERR_TRANS_ABORT,
	PM_ERR_TRANS_TYPE,
	PM_ERR_TRANS_COMMITING,
	/* Packages */
	PM_ERR_PKG_NOT_FOUND,
	PM_ERR_PKG_INVALID,
	PM_ERR_PKG_OPEN,
	PM_ERR_PKG_LOAD,
	PM_ERR_PKG_INSTALLED,
	PM_ERR_PKG_CANT_FRESH,
	PM_ERR_PKG_INVALID_NAME,
	PM_ERR_PKG_CORRUPTED,
	/* Groups */
	PM_ERR_GRP_NOT_FOUND,
	/* Dependencies */
	PM_ERR_UNSATISFIED_DEPS,
	PM_ERR_CONFLICTING_DEPS,
	PM_ERR_FILE_CONFLICTS,
	/* Misc */
	PM_ERR_USER_ABORT,
	PM_ERR_INTERNAL_ERROR,
	PM_ERR_LIBARCHIVE_ERROR,
	PM_ERR_DISK_FULL,
	PM_ERR_DB_SYNC,
	PM_ERR_RETRIEVE,
	PM_ERR_PKG_HOLD,
	/* Configuration file */
	PM_ERR_CONF_BAD_SECTION,
	PM_ERR_CONF_LOCAL,
	PM_ERR_CONF_BAD_SYNTAX,
	PM_ERR_CONF_DIRECTIVE_OUTSIDE_SECTION
} pm_errno;

char *alpm_strerror(int err);

#ifdef __cplusplus
}
#endif
#endif /* _ALPM_H */

/* vim: set ts=2 sw=2 noet: */

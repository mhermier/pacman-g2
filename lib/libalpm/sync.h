/*
 *  sync.h
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
#ifndef _ALPM_SYNC_H
#define _ALPM_SYNC_H

#include "db.h"
#include "package.h"
#include "trans.h"
#include "alpm.h"

typedef struct __syncpkg_t { /* ORE: not used for now */
	pmpkg_t *pkg;
	pmdb_t *db;
} pmsyncpkg_t;

typedef struct __pmsync_t {
	unsigned char type;
	pmpkg_t *lpkg;
	pmpkg_t *spkg;
	pmdb_t *dbs; /* ORE: not used for now */
} pmsync_t;

pmsync_t *sync_new(int type, pmpkg_t *lpkg, pmpkg_t *spkg);

PMList *sync_load_archive(char *archive);

/*int sync_findpkg(char *name, PMList *dbs, pmsyncpkg_t **sync);
pmsyncpkg_t *find_pkginsync(char *needle, PMList *haystack);
PMList *rm_pkginsync(char *needle, PMList *haystack);*/

int sync_sysupgrade(PMList **data);

int sync_addtarget(pmdb_t *db, PMList *dbs_sync, pmtrans_t *trans, char *name);
int sync_prepare(pmdb_t *db, pmtrans_t *trans, PMList **data);
int sync_commit(pmdb_t *db, pmtrans_t *trans);

#endif /* _ALPM_SYNC_H */

/* vim: set ts=2 sw=2 noet: */

/*
 *  error.c
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

#include "alpm.h"

char *alpm_strerror(int err)
{
	switch(err) {
		/* System */
		case PM_ERR_MEMORY:
			return "out of memory!";
		case PM_ERR_SYSTEM:
			return "unexpected error";
		case PM_ERR_BADPERMS:
			return "insufficient privileges";
		case PM_ERR_WRONG_ARGS:
			return "wrong or NULL argument passed";
		case PM_ERR_NOT_A_FILE:
			return "could not find or read file";
		/* Interface */
		case PM_ERR_HANDLE_NULL:
			return "library not initialized";
		case PM_ERR_HANDLE_NOT_NULL:
			return "library already initialized";
		case PM_ERR_HANDLE_LOCK:
			return "unable to lock database";
		/* Databases */
		case PM_ERR_DB_OPEN:
			return "could not open database";
		case PM_ERR_DB_CREATE:
			return "could not create database";
		case PM_ERR_DB_NULL:
			return "database not initialized";
		case PM_ERR_DB_NOT_NULL:
			return "database already registered";
		case PM_ERR_DB_NOT_FOUND:
			return "could not find database";
		case PM_ERR_DB_WRITE:
			return "could not update database";
		case PM_ERR_DB_UPTODATE:
			return "database is up to date";
		/* Cache */
		case PM_ERR_CACHE_NULL:
			return "cache not initialized";
		/* Configuration */
		case PM_ERR_OPT_LOGFILE:
		case PM_ERR_OPT_DBPATH:
		case PM_ERR_OPT_LOCALDB:
		case PM_ERR_OPT_SYNCDB:
		case PM_ERR_OPT_USESYSLOG:
			return "could not set parameter";
		/* Transactions */
		case PM_ERR_TRANS_NULL:
			return "transaction not initialized";
		case PM_ERR_TRANS_NOT_NULL:
			return "transaction already initialized";
		case PM_ERR_TRANS_DUP_TARGET:
			return "duplicate target";
		case PM_ERR_TRANS_INITIALIZED:
			return "transaction already initialized";
		case PM_ERR_TRANS_NOT_INITIALIZED:
			return "transaction not initialized";
		case PM_ERR_TRANS_NOT_PREPARED:
			return "transaction not prepared";
		case PM_ERR_TRANS_ABORT:
			return "transaction aborted";
		/* Packages */
		case PM_ERR_PKG_NOT_FOUND:
			return "could not find or read package";
		case PM_ERR_PKG_INVALID:
			return "invalid or corrupted package";
		case PM_ERR_PKG_OPEN:
			return "cannot open package file";
		case PM_ERR_PKG_LOAD:
			return "cannot load package data";
		case PM_ERR_PKG_INSTALLED:
			return "package already installed";
		case PM_ERR_PKG_CANT_FRESH:
			return "package not installed or lesser version";
		case PM_ERR_PKG_INVALID_NAME:
			return "package name is not valid";
		/* Groups */
		case PM_ERR_GRP_NOT_FOUND:
			return "group not found";
		/* Dependencies */
		case PM_ERR_UNSATISFIED_DEPS:
			return "could not satisfy dependencies";
		case PM_ERR_CONFLICTING_DEPS:
			return "conflicting dependencies";
		case PM_ERR_UNRESOLVABLE_DEPS:
			return "could not resolve dependencies";
		case PM_ERR_FILE_CONFLICTS:
			return "conflicting files";
		/* Miscellaenous */
		case PM_ERR_USER_ABORT:
			return "user aborted";
		case PM_ERR_LIBARCHIVE_ERROR:
			return "libarchive error";
		case PM_ERR_INTERNAL_ERROR:
			return "internal error";
		case PM_ERR_XXX:
		default:
			return "unexpected error";
	}
}

/* vim: set ts=2 sw=2 noet: */

AUTOMAKE_OPTIONS = gnu
DEFINES = -pedantic -D_GNU_SOURCE
AM_CFLAGS = $(DEFINES) \
	    -I$(top_srcdir)/lib/libftp
SUBDIRS = po

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

TARGETS = \
	add.c \
	backup.c \
	be_files.c \
	cache.c \
	conflict.c \
	db.c \
	deps.c \
	error.c \
	group.c \
	handle.c \
	list.c \
	log.c \
	md5.c \
	md5driver.c \
	package.c \
	packages_transaction.c \
	pacman.c \
	provide.c \
	remove.c \
	server.c \
	sha1.c \
	sync.c \
	trans.c \
	trans_sysupgrade.c \
	util.c \
	versioncmp.c

lib_LTLIBRARIES = libpacman.la

include_HEADERS = pacman.h

libpacman_la_SOURCES = $(TARGETS)

libpacman_la_LDFLAGS = -no-undefined -version-info $(PM_VERSION_INFO)
libpacman_la_LIBADD = $(top_builddir)/lib/libftp/libftp.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = pacman.pc

if HAS_DOXYGEN
all: doxygen.in

doxygen.in:
	doxygen Doxyfile

endif

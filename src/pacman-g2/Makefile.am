bin_PROGRAMS = pacman-g2

if LINKSTATIC
bin_PROGRAMS += pacman-g2.static
endif

SUBDIRS = po

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

AM_CFLAGS = -D_GNU_SOURCE \
	-I$(top_srcdir)/lib/libpacman

pacman_g2_SOURCES = \
	add.c \
	conf.c \
	deptest.c \
	download.c \
	list.c \
	log.c \
	package.c \
	pacman-g2.c \
	ps.c \
	query.c \
	remove.c \
	sync.c \
	trans.c \
	upgrade.c \
	util.c

pacman_g2_static_SOURCES = $(pacman_g2_SOURCES)

pacman_g2_LDADD = \
	$(top_builddir)/lib/libpacman/libpacman.la

pacman_g2_static_LDADD = $(pacman_g2_LDADD)

pacman_g2_static_LDFLAGS = -all-static $(LDFLAGS)

install-exec-hook:
	ln -sf pacman-g2 $(DESTDIR)$(bindir)/pacman


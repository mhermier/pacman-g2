#!/bin/sh -ex

if [ "$1" == "--dist" ]; then
	if [ -d ../releases ]; then
		release="yes"
	fi
	ver=`grep AC_INIT configure.ac|sed 's/.*, \([0-9\.]*\), .*/\1/'`
	if [ ! "$release" ]; then
		ver="${ver}_`date +%Y%m%d`"
		sed "s/@PACKAGE_VERSION@/$ver" dist/FrugalBuild.in >
			dist/FrugalBuild
	fi
	darcs changes >_darcs/current/ChangeLog
	darcs dist -d pacman-$ver
	rm _darcs/current/ChangeLog
	if [ "$release" ]; then
		dest="../releases"
	else
		dest="dist"
	fi
	mv pacman-$ver.tar.gz $dest
	if [ ! "$release" ]; then
		echo "Now type: 'cd dist; makepkg -ci'."
	fi
	exit 0
fi

#intltoolize -f -c
libtoolize -f -c
aclocal --force
autoheader -f
autoconf -f
automake -a -c --gnu --foreign

if [ "$1" == "--darcs" ]; then
	rm -rf autom4te.cache
fi

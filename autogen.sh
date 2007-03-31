#!/bin/sh -e

cd `dirname $0`

if [ "$1" == "--dist" ]; then
	if [ -d ../releases ]; then
		release="yes"
	fi
	ver=`grep AC_INIT configure.ac|sed 's/.*, \([0-9\.]*\), .*/\1/'`
	if [ ! "$release" ]; then
		ver="${ver}_`date +%Y%m%d`"
	fi
	darcs changes >_darcs/current/ChangeLog
	darcs dist -d pacman-g2-$ver
	rm _darcs/current/ChangeLog
	if [ "$release" ]; then
		dest="../releases"
		gpg --comment "See http://ftp.frugalware.org/pub/README.GPG for info" \
			-ba -u 20F55619 pacman-g2-$ver.tar.gz
		mv pacman-g2-$ver.tar.gz.asc $dest
	else
		dest="dist"
	fi
	mv pacman-g2-$ver.tar.gz $dest
	if [ ! "$release" ]; then
		sed "s/@PACKAGE_VERSION@/$ver/;
			s/@SHA1SUM@/`sha1sum $dest/pacman-g2-$ver.tar.gz|sed 's/  .*//'`/" \
			dist/FrugalBuild.in > dist/FrugalBuild
		echo "Now type: 'cd dist; makepkg -ci'."
	fi
	exit 0
elif [ "$1" == "--gettext-only" ]; then
	sh autoclean.sh
	for i in lib/libalpm/po src/pacman-g2/po
	do
		cd $i
		mv Makevars Makevars.tmp
		package=`pwd|sed 's|.*/\(.*\)/.*|\1|'`
		cp /usr/bin/intltool-extract ./
		intltool-update --pot --gettext-package=$package
		rm intltool-extract
		if [ "$2" != "--pot-only" ]; then
		for j in *.po
		do
			if msgmerge $j $package.pot -o $j.new; then
				mv -f $j.new $j
				echo -n "$i/$j: "
				msgfmt -c --statistics -o $j.gmo $j
				rm -f $j.gmo
			else
				echo "msgmerge for $j failed!"
				rm -f $j.new
			fi
		done
		fi
		mv Makevars.tmp Makevars
		cd - >/dev/null
	done
	# FIXME: implement --pot-only for po4a, too
	[ "$2" == "--pot-only" ] && exit 0
	cd doc
	po4a -k 0 po4a.cfg
	cd po
	for i in *po
	do
		if msgmerge $i $package.pot -o $i.new; then
			mv -f $i.new $i
			echo -n "man/$i: "
			msgfmt -c --statistics -o $i.gmo $i
			rm -f $i.gmo
		else
			echo "msgmerge for $i failed!"
			rm -f $i.new
		fi
	done
	exit 0
fi

# copy in the po files

po_dir=~/darcs/translations/po

if [ -d $po_dir ]; then
	: > lib/libalpm/po/LINGUAS
	: > src/pacman-g2/po/LINGUAS
	for i in $(/bin/ls $po_dir/pacman)
	do
		cp $po_dir/pacman/$i/libalpm.po lib/libalpm/po
		echo $i >> lib/libalpm/po/LINGUAS
		cp $po_dir/pacman/$i/pacman-g2.po src/pacman-g2/po
		echo $i >> src/pacman-g2/po/LINGUAS
	done
else
	echo "WARNING: no po files will be used"
fi

# generate the pot files

for i in lib/libalpm/po src/pacman-g2/po
do
	cd $i
	mv Makevars Makevars.tmp
	package=`pwd|sed 's|.*/\(.*\)/.*|\1|'`
	cp /usr/bin/intltool-extract ./
	intltool-update --pot --gettext-package=$package
	rm intltool-extract
	mv Makevars.tmp Makevars
	cd - >/dev/null
done

libtoolize -f -c
aclocal --force
autoheader -f
autoconf -f
cp -f $(dirname $(which automake))/../share/automake/mkinstalldirs ./
cp -f $(dirname $(which automake))/../share/gettext/config.rpath ./
automake -a -c --gnu --foreign

if [ "$1" == "--darcs" ]; then
	rm -rf autom4te.cache
fi

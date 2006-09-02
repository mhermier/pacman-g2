#!/usr/bin/env python

import os, sys

class author:
	def __init__(self):
		self.name = ""
		self.years = []

class authors:
	def __init__(self):
		self.authors = []
		# aliases list generated by DARCS_DONT_ESCAPE_ANYTHING="1" dr chan|grep '^[A-Z]'|sed 's/.*  //'|sort -u
		self.aliases = {
				"alex_extreme <alex.extreme2@gmail.com>":"Alex Smith <alex@alex-smith.me.uk>",
				"aurelien":"Aurelien Foret <orelien@chez.com>",
				"BMH1980 <bmh1980@frugalware.org>":"Marcus Habermehl <bmh1980@frugalware.org>",
				"Christian Hamar alias krix <krics@linuxforum.hu>":"Christian Hamar <krics@linuxforum.hu>",
				"DNAku <David.Kimpe@DistroTalk.net>":"David Kimpe <dnaku@frugalware.org>",
				"judd":"Judd Vinet <jvinet@zeroflux.org>",
				"VMiklos <vmiklos@frugalware.org>":"Miklos Vajna <vmiklos@frugalware.org>",
				"voroskoi <voroskoi@frugalware.org>":"Andras Voroskoi <voroskoi@frugalware.org>"
				}
	def add(self, name, year):
		if name == "anonymous":
			# lol @ cvs
			return
		found = False
		for i in self.authors:
			if i.name == name:
				found = True
				if year not in i.years:
					i.years.append(year)
		if not found:
			i = author()
			i.name = name
			i.years.append(year)
			self.authors.append(i)
	def dump(self):
		self.authors.reverse()
		for i in self.authors:
			sys.stdout.write("Copyright (c) ")
			i.years.reverse()
			for j in i.years:
				if j != i.years[-1]:
					sys.stdout.write("%s, " % j)
				else:
					sys.stdout.write("%s" % j)
			sys.stdout.write(" by ")
			if i.name in self.aliases.keys():
				i.name = self.aliases[i.name]
			sys.stdout.write("%s\n" % i.name)

def gencopy(fn):
	names = authors()
	socket = os.popen("darcs chan %s" % fn, "r")
	# skip the first 2 lines
	for i in range(2):
		socket.readline()
	while True:
		line = socket.readline()
		if not line:
			break
		if line[:1].isupper():
			names.add(line.split("  ")[-1].strip(), line.split("  ")[-2].split(" ")[-1])
	socket.close()
	names.dump()

for i in ["lib/libalpm", "scripts", "src"]:
	for root, dirs, files in os.walk(i):
		for file in files:
			if file[-2:] == ".c":
				print "==> %s/%s:" % (root, file)
				gencopy("%s/%s" % (root, file))

import glob
import sys

from distutils.core import setup

setup(
	name = 'operapass',
	version = '1.0',
	author = 'Martin Tournoij',
	author_email = 'martin@arp242.net',
	url = 'http://code.google.com/p/operapass/',
	scripts = ('operapass-dump', 'operapass-tk'),
	packages = ('operapass',),
	#data_files = (),
)

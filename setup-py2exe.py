####
#### Note: mailtray runs fine with Windows. I just can't get py2exe to work
####

import glob
import sys
from distutils.core import setup

import py2exe

ver = '%s%s' % (sys.version_info.major, sys.version_info.minor)

setup(
	name = 'operapass',
	version = '1.0',
	author = 'Martin Tournoij',
	author_email = 'martin@arp242.net',
	url = 'http://code.google.com/p/operapass/',
	scripts = ('operapass-dump', 'operapass-tk'),
	packages = ('operapass',),
	#data_files = (),

	options = {
		'py2exe': {
			#'compressed': True,
			#'optimize': 2,
			#'unbuffered': True,

			# Turning this one causes issues with pygtk
			#'bundle_files': 1,

			#'dll_excludes': ['POWRPROF.DLL', 'MSWSOCK.DLL', ],
			#'excludes': ['_ssl', 'doctest', 'pdb', 'unittest', 'difflib', 'inspect',
			#	'pyreadline', 'optparse', 'calendar', 'pyexpat', 'bz2',],
		}
	}
)

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
    version = '1.2',
    author = 'atmouse',
    author_email = 'atmouse.cc@gmail.com',
    url = 'https://github.com/atmouse-',
    scripts = ('operapass-dump',),
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
            #   'pyreadline', 'optparse', 'calendar', 'pyexpat', 'bz2',],
        }
    }
)

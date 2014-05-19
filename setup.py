import glob
import sys

from distutils.core import setup

setup(
    name = 'operapass',
    version = '1.2',
    author = 'atmouse',
    author_email = 'xxx@gmail.com',
    url = 'https://github.com/atmouse-',
    scripts = ('operapass-dump',),
    packages = ('operapass',),
    #data_files = (),
)

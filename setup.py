from __future__ import print_function

import codecs
import os
import sys

try:
    from setuptools import find_packages, setup
except ImportError:
    print('`setuptools` is required for installation.\n'
          'You can install it using pip.', file=sys.stderr)
    sys.exit(1)


# file paths
here = os.path.abspath(os.path.dirname(__file__))
readme_file = os.path.join(here, 'README.md')
donatello_dir = os.path.join(here, 'donatello')
version_file = os.path.join(donatello_dir, '_version.py')

# setup args
pypi_name = 'donatello'
description = 'TODO'
src_license = 'MIT'
author = 'Brian Welch'
author_email = 'welch18@vt.edu'
url = 'https://github.com/welchbj/donatello'
install_requires = ['colorama', 'ttable']

with codecs.open(version_file, encoding='utf-8') as f:
    exec(f.read())  # loads __version__ and __version_info__
    version = __version__ # noqa

with codecs.open(readme_file, encoding='utf-8') as f:
    long_description = f.read()

entry_points = {
    'console_scripts': [
        'donatello = donatello.__main__:main',
    ]
}

classifiers = [
    'License :: OSI Approved :: MIT License',
    # TODO
]

setup(
    name=pypi_name,
    version=version,
    description=description,
    long_description=long_description,
    author=author,
    author_email=author_email,
    url=url,
    license=src_license,
    install_requires=install_requires,
    packages=find_packages(exclude=['tests', '*.tests', '*.tests.*']),
    entry_points=entry_points,
    classifiers=classifiers
)

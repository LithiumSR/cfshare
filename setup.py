#!/usr/bin/env python3

__author__ = "Leonardo Sarra"
__copyright__ = "Copyright 2020, Leonardo Sarra"
__license__ = "MIT"
__email__ = "leonardosarra@outlook.com"

from setuptools import setup

setup(
    name='cfshare',
    version="1.0",
    license=__license__,
    description='Split files in multiple encrypted shares and reconstruct the original file from a subset of them',
    author=__author__,
    author_email=__email__,
    url='https://github.com/lithiumsr/cfshare',
    download_url='https://github.com/lithiumsr/cfshare/archive/master.tar.gz',
    package_dir={'cfshare': 'cfshare', 'secret_sharing': 'secret_sharing'},
    packages=['cfshare', 'secret_sharing'],
    install_requires=[
        'cryptography',
    ],
    entry_points={
        'console_scripts': ['cfshare = cfshare.main:main']
    }
)

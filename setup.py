#!/usr/bin/env python3

__author__ = "Leonardo Sarra"
__copyright__ = "Copyright 2020, Leonardo Sarra"
__license__ = "MIT"
__email__ = "leonardosarra@outlook.com"

from setuptools import setup

setup(
    name='crypto_split',
    version="0.1",
    license=__license__,
    description='Split files in multiple encrypted fragments and reconstruct the original file from a subset of the fragments',
    author=__author__,
    author_email=__email__,
    url='https://github.com/lithiumsr/crypto_split',
    download_url='https://github.com/lithiumsr/crypto_split/archive/master.tar.gz',
    package_dir={'crypto_split': 'crypto_split', 'secret_sharing': 'secret_sharing'},
    packages=['crypto_split', 'secret_sharing'],
    install_requires=[
        'cryptography',
    ],
    entry_points={
        'console_scripts': ['cryptosplit = crypto_split.main:main']
    }
)

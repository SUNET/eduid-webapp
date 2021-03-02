#!/usr/bin/env python
import os
from pathlib import PurePath
from typing import List

from setuptools import setup, find_packages

version = '0.2.27'


def load_requirements(path: PurePath) -> List[str]:
    """ Load dependencies from a requirements.txt style file, ignoring comments etc. """
    res = []
    with open(path) as fd:
        for line in fd.readlines():
            while line.endswith('\n') or line.endswith('\\'):
                line = line[:-1]
            line = line.strip()
            if not line or line.startswith('-') or line.startswith('#'):
                continue
            res += [line]
    return res


here = PurePath(__file__)
README = open(here.with_name('README.txt')).read()

install_requires = load_requirements(here.with_name('requirements.txt'))
test_requires = load_requirements(here.with_name('test_requirements.txt'))

setup(
    name='eduid-webapp',
    version=version,
    license='bsd',
    url='https://www.github.com/SUNET/',
    author='SUNET',
    author_email='',
    description='web apps for eduID',
    classifiers=['Framework :: Flask',],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    namespace_packages=['eduid_webapp'],
    zip_safe=False,
    include_package_data=True,
    install_requires=install_requires,
    test_requires=test_requires,
    extras_require={'testing': []},
)

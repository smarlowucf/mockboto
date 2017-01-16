#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import find_packages, setup

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    'boto3',
]

test_requirements = [
    'coverage',
    'nose',
]

dev_requirements = [
    'bumpversion',
    'flake8',
    'pip>=7.0.0',
    'Sphinx'
] + test_requirements

setup(
    name='mockboto3',
    version='0.1.1',
    description="Python package for mocking the boto3 library.",
    long_description=readme + '\n\n' + history,
    author="Sean Marlow",
    author_email='sean.marlow@suse.com',
    url='https://github.com/smarlowucf/mockboto3',
    packages=find_packages(),
    package_dir={'mockboto3':
                 'mockboto3'},
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        'dev': dev_requirements
    },
    license="MIT license",
    zip_safe=False,
    keywords='mockboto3',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Testing',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    test_suite='nose.collector',
    tests_require=test_requirements
)

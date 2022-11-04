#!/usr/bin/env python3
# -*- coding: UTF8 -*-

from setuptools import setup, find_packages
import os
import sys

requirements = [x.strip() for x in open("requirements.txt", "r").readlines()]
#requirements = [f"{line.split('#egg=')[-1]} @ {line}" if "#egg=" in line else line for line in requirements]

setup(
    name='pupy',
    version='3.0.0',
    packages=find_packages(where='.', include=['pupy*']), 
    package_data={'pupy': ['conf/**', 'external/**', 'packages/**', 'library_patches_py3/**', 'library_patches_py2/**']},
    license_files = ('LICENSE'),
    author='n1nj4sec',
    author_email='contact@n1nj4.eu',
    description='Pupy C2 is an opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool in python',
    #long_description='Pupy C2 Framework',
    #long_description_content_type='text/x-rst',
    url='https://github.com/n1nj4sec/pupy',
    keywords=["python", "pentest", "cybersecurity", "redteam", "C2", "command and control", "post-exploitation"],
    entry_points={
        'console_scripts': [
            'pupysh = pupy.cli.pupysh:main'
        ]
    },
    install_requires=requirements
)

#!/usr/bin/env python3
# -*- coding: UTF8 -*-

from setuptools import setup, find_packages
import os
import sys

requirements = [x.strip() for x in open("requirements.txt", "r").readlines()]
#requirements = [f"{line.split('#egg=')[-1]} @ {line}" if "#egg=" in line else line for line in requirements]

def generate_data_files():
    data_files = [("data", ["pupy/pupy.conf.default"])]
    data_dirs = ('pupy/library_patches_py3', 'pupy/library_patches_py2', 'pupy/packages')
    for data_dir in data_dirs:
        for path, dirs, files in os.walk(data_dir):
            if "__pycache__" in path:
                continue
            install_dir =  os.path.join("data", path)
            list_entry = (install_dir, [os.path.join(path, f) for f in files if not f.startswith('.')])
            data_files.append(list_entry)
    return data_files

setup(
    name='pupy',
    version='3.0.0',
    packages=find_packages(where='pupy', include=['pupy*', 'pupylib*', 'network*', 'commands*', 'modules*', 'scriptlets*', 'triggers*']),
    package_dir={"": "pupy"},
    data_files=generate_data_files(),
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
            'pupysh = pupylib.cli.pupysh:main'
        ]
    },
    install_requires=requirements
)

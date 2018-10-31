# Pupy

[![Build Status](https://api.travis-ci.org/n1nj4sec/pupy.svg?branch=unstable)](https://travis-ci.org/n1nj4sec/pupy)

## Installation

Installation instructions are on the wiki, in addition to all other documentation. For maximum compatibility, it is recommended to use Docker Compose.

[Refer to the wiki](https://github.com/n1nj4sec/pupy/wiki/Installation)

## Description

Pupy is a cross-platform, multi function RAT and post-exploitation tool mainly written in python. It features an all-in-memory execution guideline and leaves a very low footprint. Pupy can communicate using multiple transports, migrate into processes using reflective injection, and load remote python code, python packages and python C-extensions from memory.

## Features

- Windows payload can load the entire Python interpreter from memory using a reflective DLL.
	- Pupy does not touch the disk.

- Can be packed into a single .py file and run without any dependencies other than the python standard library on all OSes.
	- PyCrypto gets replaced by pure Python AES & RSA implementations when unavailable.

- Reflectively migrate into other processes.
- Remotely import pure python packages (.py, .pyc) and compiled python C extensions (.pyd, .so) from memory.
	- Imported python modules do not touch the disk.

- Easily extensible, modules are simple to write and are sorted by os and category.

- Modules can directly access python objects on the remote client using [rpyc](https://github.com/tomerfiliba/rpyc).

- Access remote objects interactively from the pupy shell and get auto-completion of remote attributes.

- Communication transports are modular and stackable. Exfiltrate data using HTTP over HTTP over AES over XOR, or any combination of the available transports.

- Communicate using obfsproxy [pluggable transports.](https://www.torproject.org/docs/pluggable-transports.html.en)

- Execute noninteractive commands on multiple hosts at once.

- Commands and scripts running on remote hosts are interruptible.
- Auto-completion for commands and arguments.
- Custom config can be defined: command aliases, modules. automatically run at connection, etc.

- Multiple Target Platforms:

| Platform | Support Status |
|---|---|
Windows XP | Supported
Windows 7 | Supported
Windows 8 | Supported
Windows 10 | Supported
Linux | Supported
Mac OSX | Limited Support
Android | Limited Support

## Documentation

All documentation can be found on the wiki.

[Refer to the wiki](https://github.com/n1nj4sec/pupy/wiki)

## FAQ

> Does the server work on windows?

Pupy has not been tested on Windows. Theoretically, it should work on any platform that supports Docker and Docker Compose. However, you will need to adapt the Docker Compose installation instructions for the Windows platform.

> I can't install Pupy. The installation fails.

1. Please refer to the wiki. It is possible that your answer is there.
2. Search the Github issues and see if your issue was already solved.
3. If you issue was not solved, open a new issue following the [issue guidelines](https://github.com/n1nj4sec/pupy/wiki/Issue-Guidelines).

If you do not follow the steps, you issue will be closed.

> Android and/or Mac OSX payloads and modules don't work.

Pupy has _limited_ support for Android and OSX. Support for these platforms is not well maintained and may break intermittently. Some modules (i.e. keylogger) may be missing for these platforms.

## Development

If some of you want to participate to pupy development, don't hesitate ! All help is greatly appreciated and I will review every pull request.

Also there is small [note](https://github.com/n1nj4sec/pupy/wiki/Development) about development. Please run flake8 before doing any commits.
File with config is [here](pupy/tox.ini).

## Contact

| Platform | Contact Info |
|---|---|
Email | contact@n1nj4.eu
Twitter | https://twitter.com/n1nj4sec

This project is a [personal development](https://en.wikipedia.org/wiki/Personal_development), please respect its philosophy and don't use it for evil purposes!

## Special thanks

Special thanks to all contributors that helps me improve pupy and make it an even better tool ! :)


TAGS: ((Note: Remove this.)
post exploitation framework
RAT
remote administration tool
)

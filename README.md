[![Build Status](https://api.travis-ci.org/n1nj4sec/pupy.svg?branch=unstable)](https://travis-ci.org/n1nj4sec/pupy)

# Pupy

## Quick install and configure
You have multiple ways for installing pupy including docker. cf. the wiki
If you want a simple installation in a virtualenv with pre-built binaries, please use :
```
apt-get install git libssl1.0-dev libffi-dev python-dev python-pip tcpdump python-virtualenv
git clone --recursive https://github.com/n1nj4sec/pupy
cd pupy
python create-workspace.py -DG pupyw
```

## Description

Pupy is an opensource, cross-platform (Windows, Linux, OSX, Android), multi function RAT (Remote Administration Tool) and post-exploitation tool mainly written in python. It features an all-in-memory execution guideline and leaves very low footprint. Pupy can communicate using various transports, migrate into processes (reflective injection), load remote python code, python packages and python C-extensions from memory.
Pupy modules can transparently access remote python objects using rpyc to perform various interactive tasks.
Pupy can generate payloads in multiple formats like PE executables, reflective
DLLs, pure python files, powershell, apk, ...  When you package a payload, you
can choose a launcher (connect, bind, ...), a transport (ssl, http, rsa, obfs3,
scramblesuit, ...) and a number of "scriptlets". Scriptlets are python scripts
meant to be embedded to perform various tasks offline (without requiring a
session), like starting a background script, adding persistence, starting a
keylogger, detecting a sandbox, ...

## Installation

[Refer to the wiki](https://github.com/n1nj4sec/pupy/wiki/Installation)

## Features

- Multi-platform (tested on windows xp, 7, 8, 10, kali linux, ubuntu, osx, android)
- On windows, the Pupy payload can be compiled as a reflective DLL and the whole python interpreter is loaded from memory. Pupy does not touch the disk :)
- pupy can also be packed into a single .py file and run without any dependencies other that the python standard library on all OS
	- pycrypto gets replaced by pure python aes && rsa implementations when unavailable
- Pupy can reflectively migrate into other processes
- Pupy can remotely import, from memory, pure python packages (.py, .pyc) and compiled python C extensions (.pyd, .so). The imported python modules do not touch the disk.
- Pupy is easily extensible, modules are quite simple to write, sorted by os and category.
- A lot of awesome modules are already implemented!
- Pupy uses [rpyc](https://github.com/tomerfiliba/rpyc) and a module can directly access python objects on the remote client
  - We can also access remote objects interactively from the pupy shell and you even get auto-completion of remote attributes!
- Communication transports are modular, stackable and awesome. You could exfiltrate data using HTTP over HTTP over AES over XOR. Or any combination of the available transports !
- Pupy can communicate using obfsproxy [pluggable transports](https://www.torproject.org/docs/pluggable-transports.html.en)
- All the non interactive modules can be dispatched to multiple hosts in one command
- Commands and scripts running on remote hosts are interruptible
- Auto-completion for commands and arguments
- Custom config can be defined: command aliases, modules automatically run at connection, ...
- Interactive python shells with auto-completion on the all in memory remote python interpreter can be opened
- Interactive shells (cmd.exe, /bin/bash, ...) can be opened remotely. Remote shells on Unix & windows clients have a real tty with all keyboard signals working fine just like a ssh shell
- Pupy can execute PE exe remotely and from memory (cf. ex with mimikatz)
- Pupy can generate payloads in various formats : apk,lin_x86,lin_x64,so_x86,so_x64,exe_x86,exe_x64,dll_x86,dll_x64,py,pyinst,py_oneliner,ps1,ps1_oneliner,rubber_ducky
- Pupy can be deployed in memory, from a single command line using pupygen.py's python or powershell one-liners.
- "scriptlets" can be embeded in generated payloads to perform some tasks "offline" without needing network connectivity (ex: start keylogger, add persistence, execute custom python script, check_vm ...)
- tons of other features, check out the implemented modules

## Implemented Transports
All transports in pupy are stackable. This mean that by creating a custom
transport conf (pupy/network/transport/<transport_name>/conf.py), you can make
you pupy session looks like anything. For example you could stack HTTP over
HTTP over base64 over HTTP over AES over obfs3 :o)

- rsa
	- A layer with authentication & encryption using RSA and AES256, often stacked with other layers
- aes
	- layer using a static AES256 key
- ssl (the default one)
	- TCP transport wrapped with SSL
- ssl_rsa
	- same as ssl but stacked with a rsa layer
- http
	- layer making the traffic look like HTTP traffic. HTTP is stacked with a rsa layer
- obfs3
	- [A protocol to keep a third party from telling what protocol is in use based on message contents](https://gitweb.torproject.org/pluggable-transports/obfsproxy.git/tree/doc/obfs3/obfs3-protocol-spec.txt)
	- obfs3 is stacked with a rsa layer for a better security
- scramblesuit
	- [A Polymorphic Network Protocol to Circumvent Censorship](http://www.cs.kau.se/philwint/scramblesuit/)
	- scramblesuit is stacked with a rsa layer for a better security
- udp
	- rsa layer but over UDP (could be buggy, it doesn't handle packet loss yet)
- other
	- Other layers doesn't really have any interest and are given for code examples : (dummy, base64, XOR, ...)

## Implemented Launchers (not up to date, cf. ./pupygen.py -h)

Launchers allow pupy to run custom actions before starting the reverse connection
- connect
	- Just connect back
- bind
	- Bind payload instead of reverse
- auto_proxy
	- Retrieve a list of possible SOCKS/HTTP proxies and try each one of them. Proxy retrieval methods are: registry, WPAD requests, gnome settings, HTTP_PROXY env variable

## Documentation

There is no documentation. Sorry. But you can help us to write one.

[Refer to the wiki](https://github.com/n1nj4sec/pupy/wiki)

### Some screenshots (not up to date)

[Screenshot section on the wiki](https://github.com/n1nj4sec/pupy/wiki)

## FAQ

> Does the server work on windows?

No. (Or maybe, but you shouldn't)

> I can't install it, how does it work?

First try to have a look at the Installation section in the wiki.
There are not so many things which can go wrong. Check:

1. Git checkout was successful. From time to time submodules may be rebased and checkout may fail in between.
2. You do have python 2.7, toolchains docker etc.
3. You have enough space to checkout and build all the things. At least 5-6 GB for docker images and 500 MB for pupy.
4. From time to time some python deps may become broken. In such case try to use version from repo.

## Development

If some of you want to participate to pupy development, don't hesitate ! All help is greatly appreciated and I will review every pull request.

Also there is small [note](pupy/DEVELOPMENT.md) about development. Please run flake8 before doing any commits.
File with config is [here](pupy/tox.ini).

## Contact

by mail: contact@n1nj4.eu
on Twitter: [Follow me on twitter](https://twitter.com/n1nj4sec)

This project is a [personal development](https://en.wikipedia.org/wiki/Personal_development), please respect its philosophy and don't use it for evil purposes!

## Special thanks

Special thanks to all contributors that helps me improve pupy and make it an even better tool ! :)

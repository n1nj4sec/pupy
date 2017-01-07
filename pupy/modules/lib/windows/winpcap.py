#!/usr/bin/env python
# -*- coding: UTF8 -*-
from pupylib import *

def init_winpcap(module):
    if module.client.is_windows():
        if module.client.is_windows():
            if not module.client.conn.modules["os.path"].exists("C:\\Windows\\system32\\Packet.dll") and not module.client.conn.modules["os.path"].exists("C:\\Windows\\system32\\NPcap\\Packet.dll"):
                raise PupyModuleError("WinPcap is not installed !. You should download/upload NPcap (https://github.com/nmap/npcap/releases) and install it silently (with the /S flag) ")
            if module.client.conn.modules["os.path"].exists("C:\\Windows\\system32\\NPcap"):
                module.client.conn.modules["os"].environ["Path"]+=";C:\\Windows\\system32\\NPcap"
            if not module.client.conn.modules['ctypes'].windll.Shell32.IsUserAnAdmin():
                module.warning("you are running this module without beeing admin")

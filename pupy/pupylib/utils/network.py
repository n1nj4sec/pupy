# -*- coding: UTF8 -*-
import subprocess
import re

def get_local_ip(iface = 'eth0'):
    try:
        return re.findall("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", subprocess.check_output(["ifconfig", iface]).split("\n")[1])[0]
        #TODO same for windows
    except Exception:
        return None

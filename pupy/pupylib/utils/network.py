# -*- coding: UTF8 -*-
import subprocess
import re

def get_local_ip(iface = None):
    try:
        if iface:
            return re.findall("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", subprocess.check_output(["ifconfig", iface]).split("\n")[1])[0]
        else:
            return [ x for x in re.findall("inet addr:([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", subprocess.check_output(["ifconfig"])) if x!="127.0.0.1"][0]
        #TODO same for windows
    except Exception:
        return None

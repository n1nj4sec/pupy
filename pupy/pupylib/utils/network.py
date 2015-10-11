# -*- coding: UTF8 -*-
import subprocess

def get_local_ip(iface = 'eth0'):
	try:
		return subprocess.check_output(["ifconfig", iface]).split("\n")[1].split()[1][5:]
		#TODO same for windows
	except Exception:
		return None

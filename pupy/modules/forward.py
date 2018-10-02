# -*- coding: utf-8 -*-

import traceback

from pupylib import getLogger

from pupylib.PupyModule import (
    PupyModule, config, PupyArgumentParser
)

import pyuvproxy

__class_name__ = 'Forward'

logger = getLogger('mod_forward')

@config(cat='network', tags=['forward', 'pivot'])
class Forward(PupyModule):
    ''' Local/remote port forwarding and SOCKS proxy '''
    dependencies = {
        'all': ['pyuv', 'pyuvproxy'],
    }

    is_module = False

    @classmethod
    def init_argparse(cls):
        example = """Examples:
>> run forward -L 1234
Open a Socks proxy on local port 1234. Connection output from the target.
>> run forward -CL 1234
Close the local Socks proxy opened on 1234
>> run forward -R 1234
Open a Socks proxy on target (127.0.0.1:1234). Becareful with target's firewal configuration.
>> run forward -CR 1234
Stop the last proxy opened on the target
>> run forward -R 0.0.0.0:1234
Open a Socks proxy on target (0.0.0.0:1234). Need a Socks connection to target_ip:1234.
>> run forward -L 127.0.0.1:1234:192.168.0.2:8000
Local port forwarding. Listen locally on 1234 and connection establishes by the target to 192.168.0.2:8000.
        """

        parser = PupyArgumentParser(
            prog='forward', description=cls.__doc__, epilog=example
        )

        actions = parser.add_mutually_exclusive_group(required=True)
        actions.add_argument(
            '-CL', '--cancel-local',
            help='Cancel local forwarding (LPORT/LPATH)'
        )
        actions.add_argument(
            '-CR', '--cancel-remote',
            help='Cancel remote forwarding (RPORT/RPATH)'
        )

        actions.add_argument(
            '-l', '--list',
            default=False, action='store_true',
            help='List forwardings for current client'
        )

        actions.add_argument(
            '-L', '--local', help='Local port forwarding ([LHOST]:LPORT[:RHOST[:[BPORT=]RPORT]])'
            '; LPATH:RPATH'
        )

        actions.add_argument(
            '-R', '--remote', help='Remote port forwarding ([RHOST:]RPORT[:LHOST[:[BPORT=]LPORT]])'
            '; RPATH:LPATH'
        )

        actions.add_argument(
            '-VRL', '--virtual-remote-listener', help='Create virtual pupy listener',
            metavar=('PORT', 'TRANSPORT'), nargs=2
        )

        actions.add_argument(
            '-CVRL', '--cancel-virtual-remote-listener',
            metavar='PORT', help='Disable virtual pupy listener',
            type=int
        )

        cls.arg_parser = parser

    def run(self, args):
        try:
            state = self.client.conn.single(pyuvproxy.PairState)

            if args.list:
                self._list(state, args)
            else:
                self._portmap(state, args)

        except:
            traceback.print_exc()
            raise

    def _list(self, state, args):
        if not state.local:
            self.info('Forwarding was not enabled')
            return

        for port, forward in state.local.list(filter_by_local_id=state.local_id):
            self.success('L: {} -> {}'.format(port, forward))

        for port, forward in state.remote.list():
            self.success('R: {} -> {}'.format(port, forward))

    def _parse_args(self, args):
        config = None
        parts = None
        lport, lhost = None, None
        rport, rhost = None, None
        lpath, rpath = None, None
        bport = None

        if args.cancel_local or args.cancel_remote:
            config = args.cancel_local or args.cancel_remote
            try:
                lport = int(config)
                lhost = None
            except:
                lport = None
                lhost = config
        else:
            config = args.local or args.remote
            parts = config.split(':')
            lport, lhost = 1080, '127.0.0.1'
            rport, rhost = None, None
            lpath, rpath = None, None
            bport = None

            if len(parts) == 1:
                lport = int(parts[0])
            elif len(parts) == 2:
                part1, part2 = parts
                found = False
                try:
                    if '=' in part1:
                        bport, lport = part1.split('=')
                        bport = int(bport)
                        lport = int(lport)
                    else:
                        lport = int(part1)

                    try:
                        if '=' in part2:
                            bport, rport = part2.split('=')
                            bport = int(bport)
                            rport = int(rport)
                        else:
                            rport = int(part2)

                        rhost = '127.0.0.1'
                        found = True
                    except:
                        rhost = part2
                        rport = lport
                        found = True
                except:
                    try:
                        if '=' in part2:
                            bport, lport = part2.split('=')
                            bport = int(bport)
                            lport = int(lport)
                        else:
                            lport = int(part2)

                        lhost = part1
                        found = True
                    except:
                        pass

                if not found:
                    lpath, rpath = parts

            elif len(parts) == 3:
                try:
                    if '=' in parts[2]:
                        bport, rport = parts[2].split('=')
                        bport = int(bport)
                        rport = int(rport)
                    else:
                        rport = int(parts[2])

                    lport, rhost = parts[:2]

                    if '=' in lport:
                        bport, lport = lport.split('=')
                        bport = int(bport)
                        lport = int(lport)
                    else:
                        lport = int(lport)

                except:
                    lhost, lport, rhost = parts
                    if '=' in lport:
                        bport, lport = lport.split('=')
                        bport = int(bport)
                        lport = int(lport)
                    else:
                        lport = int(lport)

                    rport = lport

            elif len(parts) == 4:
                lhost, lport, rhost, rport = parts
                lport = int(lport)

                if '=' in rport:
                    bport, rport = rport.split('=')
                    bport = int(bport)
                    rport = int(rport)
                else:
                    rport = int(rport)

            else:
                raise ValueError(
                    'Invalid configuration: {}'.format(config))

        return config, parts, lport, lhost, rport, rhost, lpath, rpath, bport

    def _portmap(self, state, args):
        if len(self.job.pupymodules) > 1 and (args.local or args.cancel_local):
            raise ValueError(
                'Adding local forward for multiple modules is not supported')

        config, parts, lport, lhost, rport, rhost, lpath, rpath, bport = \
            None, None, None, None, None, None, None, None, None

        virt_port, virt_transport = None, None

        if args.virtual_remote_listener:
            virt_port = int(args.virtual_remote_listener[0])
            virt_transport = args.virtual_remote_listener[1]
        elif args.cancel_virtual_remote_listener:
            virt_port = int(args.cancel_virtual_remote_listener)
        else:
            config, parts, lport, lhost, rport, rhost, lpath, rpath, bport = self._parse_args(
                args)

        manager = self.client.pupsrv.single(pyuvproxy.ManagerState)
        rpyuvproxy = self.client.remote('pyuvproxy')

        if args.cancel_local or args.cancel_remote or args.cancel_virtual_remote_listener:
            local, remote, local_id, remote_id = state.get()

            if not local:
                self.info('Forwarding was not enabled')
                return

            if args.cancel_local:
                manager = local
            else:
                manager = remote

            try:
                if args.cancel_virtual_remote_listener:
                    local.unregister_virtual_port(virt_port)
                    remote.unbind(virt_port)
                else:
                    idx = lhost or lport
                    if manager.unbind(idx):
                        self.success('Forwarding {} removed'.format(idx))
                    else:
                        self.error(
                            'Removal failed: port {} not found'.format(idx))
            except Exception, e:
                self.error('Removal failed: {}'.format(e))

            return

        if not manager.manager:
            manager.manager = pyuvproxy.Manager()
            manager.manager.start()
            self.client.pupsrv.register_cleanup(manager.cleanup)

        if not state.local:
            state.local = manager.manager
            state.remote = rpyuvproxy.Manager()
            state.remote.start()
            state.remote_id, state.local_id = state.local.pair(
                state.remote)

            self.client.conn.register_local_cleanup(state.cleanup)
            self.client.conn.register_remote_cleanup(
                state.remote.force_stop
            )

        local, remote, local_id, remote_id = state.get()

        if args.local:
            manager = local
            id = local_id
        else:
            manager = remote
            id = remote_id

        try:
            if args.virtual_remote_listener:
                def _create_virtual_connection(peername):
                    try:
                        return self.client.pupsrv.create_virtual_connection(
                            virt_transport, '{}@{}'.format(
                                peername, self.client.node()))
                    except Exception, e:
                        logger.exception(e)
                        raise

                local.register_virtual_port(virt_port, _create_virtual_connection)
                remote.bind(id, local_address=('0.0.0.0', virt_port),
                            forward=('254.254.254.254', virt_port))

                self.success('Forwarding pupy port activated ({}: {})'.format(
                    virt_port, virt_transport))
                return

            if rport and rhost:
                forward = (rhost, rport)
            else:
                forward = None

            if lpath and rpath:
                manager.bind(id, local_address=lpath,
                             forward=rpath, bind=bport)
            else:
                manager.bind(id, local_address=(lhost, lport),
                             forward=forward, bind=bport)

            self.success('Forwarding added')

        except Exception, e:
            self.error('Forwarding failed: {}:{}'.format(type(e), e))

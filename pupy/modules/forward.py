# -*- coding: utf-8 -*-

import sys, os
from pupylib.PupyModule import *
from pupylib.PupyJob import PupyJob
from threading import Thread

try:
    import pyuvproxy
except ImportError:
    packages_all = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__), '..', 'packages', 'all'
        )
    )

    sys.path.append(packages_all)
    import pyuvproxy

__class_name__ = 'Forward'

@config(cat='network', tags=['forward', 'pivot'])
class Forward(PupyModule):
    ''' Forward local/remote network points '''
    is_module = False
    dependencies = {
        'all': [ 'pyuv', 'pyuvproxy' ],
    }

    def init_argparse(self):
        parser = PupyArgumentParser(
            prog='forward', description=self.__doc__
        )

        actions = parser.add_mutually_exclusive_group(required=True)
        actions.add_argument(
            '-CL', '--cancel-local',
            help='Cancel local forwarding (LPORT)'
        )
        actions.add_argument(
            '-CR', '--cancel-remote',
            help='Cancel remote forwarding (RPORT)'
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
        try:
            self._run(args)
        except Exception, e:
            import traceback
            traceback.print_exc()

    def _run(self, args):
        state = self.client.conn.single(pyuvproxy.PairState)

        if args.list:
            if not state.local:
                self.info('Forwarding was not enabled')
                return

            for port, forward in state.local.list(filter_by_local_id=state.local_id):
                self.success('L: {} -> {}'.format(port, forward))

            for port, forward in state.remote.list():
                self.success('R: {} -> {}'.format(port, forward))

        elif args.local or args.remote or args.cancel_local or args.cancel_remote:
            if len(self.job.pupymodules) > 1 and (args.local or args.cancel_local):
                raise ValueError('Adding local forward for multiple modules is not supported')

            if args.cancel_local or args.cancel_remote:
                config = args.cancel_local or args.cancel_remote
                lport = int(config)
            else:
                config = args.local or args.remote
                parts = config.split(':')
                lport, lhost = 1080, '127.0.0.1'
                rport, rhost = None, None

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

            manager = self.client.pupsrv.single(pyuvproxy.ManagerState)
            rpyuvproxy = self.client.conn.modules.pyuvproxy

            if args.cancel_local or args.cancel_remote:
                local, remote, local_id, remote_id = state.get()

                if not local:
                    self.info('Forwarding was not enabled')
                    return

                if args.cancel_local:
                    manager = local
                else:
                    manager = remote

                try:
                    lport = int(lport)
                    if manager.unbind(lport):
                        self.success('Forwarding {} removed'.format(lport))
                    else:
                        self.error('Removal failed: port {} not found'.format(lport))
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
                state.remote_id, state.local_id = state.local.pair(state.remote)

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
                if rport and rhost:
                    forward = (rhost, rport)
                else:
                    forward = None

                manager.bind(id, host=lhost, port=lport, forward=forward)
                self.success('Forwarding added')

            except Exception, e:
                self.error('Forwarding failed: {}:{}'.format(type(e), e))

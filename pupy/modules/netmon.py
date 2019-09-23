# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Table, MultiPart
from datetime import datetime, timedelta

NETMON_EVENT = 0x11000002

__class_name__ = 'NetMon'
__events__ = {
    NETMON_EVENT: 'netmon'
}


@config(cat='admin')
class NetMon(PupyModule):
    'Collect new IP endpoints'

    unique_instance = True

    dependencies = {
        'all': ['netmon']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='netmon', description=cls.__doc__)

        cls.arg_parser.add_argument(
            'action', choices=['start', 'stop', 'dump']
        )

    def stop_daemon(self):
        self.success('Netmon stopped')

    def render_diff(self, diff):
        if not diff:
            return

        listeners = []
        ingress = []
        egress = []
        parts = []

        for record in diff:
            new_listeners_tcp, new_listeners_udp, \
                new_ingress_tcp, new_ingress_udp, \
                new_egress_tcp, new_egress_udp = record

            for new_listeners in (new_listeners_tcp, new_listeners_udp):
                if not new_listeners:
                    continue

                for listener in new_listeners:
                    program, ip, port = listener
                    listeners.append({
                        'PRT': 'TCP' if id(new_listeners) == id(
                            new_listeners_tcp) else 'UDP',
                        'EXE': program,
                        'HOST': ip,
                        'PORT': port
                    })

            for new_ingress in (new_ingress_tcp, new_ingress_udp):
                if not new_ingress:
                    continue

                for record in new_ingress:
                    program, (ip, port), remote_ip = record
                    ingress.append({
                        'PRT': 'TCP' if id(new_ingress) == id(
                            new_ingress_tcp) else 'UDP',
                        'EXE': program,
                        'LADDR': ip,
                        'LPORT': port,
                        'RADDR': remote_ip
                    })

            for new_egress in (new_egress_tcp, new_egress_udp):
                if not new_egress:
                    continue

                for record in new_egress:
                    program, (ip, port) = record
                    egress.append({
                        'PRT': 'TCP' if id(new_egress) == id(
                            new_egress_tcp) else 'UDP',
                        'EXE': program,
                        'ADDR': ip,
                        'PORT': port,
                    })

        if listeners:
            parts.append(
                Table(
                    listeners, ['PRT', 'HOST', 'PORT', 'EXE'], 'Listeners'
                )
            )

        if ingress:
            parts.append(
                Table(
                    ingress, ['PRT', 'LADDR', 'LPORT', 'RADDR', 'EXE'], 'Ingress'
                )
            )

        if egress:
            parts.append(
                Table(
                    egress, ['PRT', 'ADDR', 'PORT', 'EXE'], 'Egress'
                )
            )

        self.log(
            MultiPart(parts)
        )

    def run(self, args):
        if args.action == 'start':
            netmon_start = self.client.remote('netmon', 'netmon_start', False)
            if netmon_start(NETMON_EVENT):
                self.success('Netmon started')
            else:
                self.error('Netmon already started')

        elif args.action == 'dump':
            netmon_dump = self.client.remote('netmon', 'netmon_dump')
            data = netmon_dump()
            if data is None:
                self.error('Netmon is not running')
            elif not data:
                self.warning('No data')
            else:
                self.render_diff(data)

        elif args.action == 'stop':
            netmon_stop = self.client.remote('netmon', 'netmon_stop', False)
            data = netmon_stop()
            if data is None:
                self.error('Netmon is not running')
                return

            elif data:
                self.warning('Summary')
                self.render_diff(data)

            self.success('Netmon stopped')



# -*- coding: utf-8 -*-

from threading import Event

from pupylib.PupyModule import PupyModule, PupyArgumentParser


__class_name__ = 'Echo'


class Echo(PupyModule):
    'Check egress (TCP/UDP) using remote echo server'

    __slots__ = ('_wait', '_abort')

    dependencies = {
        'all': ['network.lib.echo']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='echo', description=cls.__doc__)
        cls.arg_parser.add_argument(
            'host', type=str, help='IP address of pupy\'s Echo server')
        cls.arg_parser.add_argument(
            '-n', '--amount', type=int, default=4,
            help='Search at least this amount of ports before exit')

    def interrupt(self):
        self._abort()
        self._wait.set()

    def run(self, args):
        echo = self.client.remote('network.lib.echo', 'echo', False)

        self._wait = Event()

        def on_completed(tcp, http, udp):
            if self._wait.is_set():
                return

            if not any([tcp, http, udp]):
                self.warning('No connectable ports found')
                self._wait.set()
                return

            if tcp:
                self.success(
                    'TCP: {}'.format(','.join(str(x) for x in tcp)))

            if http:
                self.success(
                    'HTTP: {}'.format(','.join(str(x) for x in http)))

            if udp:
                self.success(
                    'UDP: {}'.format(','.join(str(x) for x in udp)))

            self._wait.set()

        self._abort = echo(args.host, args.amount, on_completed)
        self._wait.wait()

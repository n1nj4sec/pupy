# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
import subprocess
import threading

__class_name__="ClearLogs"

@config(cat="admin", compat=["windows"])
class ClearLogs(PupyModule):
    """ clear event logs """

    dependencies = ["pupyutils.safepopen"]
    pipe = None
    terminate = threading.Event()

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="clear_logs", description=cls.__doc__)

    def run(self, args):
        if self.client.desc['intgty_lvl'] != "High" and self.client.desc['intgty_lvl'] != "System":
            self.error('You need admin privileges to clear logs')
            return

        cmdenv = {
            'stderr': (subprocess.STDOUT),
            'universal_newlines': False,
            'shell': True
        }

        cmdargs = [
            ['System', 'wevtutil cl System'],
            ['Security', 'wevtutil cl Security'],
            ['Application', 'wevtutil cl Application']
        ]

        for cmd in cmdargs:

            self.pipe = self.client.conn.modules[
                'pupyutils.safepopen'
            ].SafePopen(cmd[1], **cmdenv)

            close_event = threading.Event()

            def on_read(data):
                self.stdout.write(data)

            def on_close():
                close_event.set()

            self.pipe.execute(on_close, on_read)
            while not (self.terminate.is_set() or close_event.is_set()):
                close_event.wait()

            if self.pipe.returncode == 0:
                self.success('Event log {} successfully deleted'.format(cmd[0]))
            else:
                self.error('Error removing {} event log: {}'.format(cmd[0], self.pipe.returncode))

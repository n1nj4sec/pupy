# -*- coding: utf-8 -*-

__class_name__="Tasks"

from pupylib.PupyModule import PupyArgumentParser, PupyModule, config
from pupylib.PupyOutput import Table, Color
from pupylib.utils.rpyc_utils import obtain

@config(cat='manage')
class Tasks(PupyModule):
    ''' Get info about registered background tasks '''

    dependencies = ['tasks']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='tasks', description=cls.__doc__)

    def run(self, args):
        pupy = self.client.remote('pupy')
        active = obtain(pupy.manager.status)
        data = []
        for task, state in active.iteritems():
            color = 'grey'
            if state['active']:
                color = 'lightgreen'
            elif state['results']:
                color = 'cyan'

            data.append({
                'TASK': Color(task, color),
                'ACTIVE': Color('Y' if state['active'] else 'N', color),
                'RESULTS': Color('Y' if state['results'] else 'N', color),
            })

        self.log(Table(data, ['TASK', 'ACTIVE', 'RESULTS']))

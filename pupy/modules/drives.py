# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="Drives"

@config(compat=[ 'linux', 'windows' ], category='admin')
class Drives(PupyModule):
    """ List valid drives in the system """

    dependencies={
        'windows': [
            'win32api', 'win32com', 'pythoncom',
            'winerror', 'wmi', 'pupwinutils.drives'
        ],
        'linux': [ 'mount' ]
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(
            prog="drives",
            description=self.__doc__
        )

    def run(self, args):
        if self.client.is_windows():
            with redirected_stdio(self.client.conn):
                self.client.conn.modules['pupwinutils.drives'].list_drives()

        elif self.client.is_linux():
            mountinfo = self.client.conn.modules['mount'].mounts()
            for fstype in mountinfo.iterkeys():
                if fstype in ('regular', 'dm'):
                    continue

                print '{}:'.format(fstype)
                for info in mountinfo[fstype]:
                    print info
                print ''

            for fstype in [ 'regular', 'dm' ]:
                if not fstype in mountinfo:
                    continue

                print '{}: '.format(fstype)
                for info in mountinfo[fstype]:
                    print info
                print ''

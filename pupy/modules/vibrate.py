# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="AndroidVibrate"

@config(compat="android", cat="troll", tags=["vibrator"])
class AndroidVibrate(PupyModule):
    """ activate the phone/tablet vibrator :) """
    dependencies=['pupydroid.vibrator']
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="vibrator", description=self.__doc__)

    def run(self, args):
        #Each element then alternates between vibrate, sleep, vibrate, sleep...
        pattern=[1000,1000,1000,1000,1000,1000,1000,1000]

        self.client.conn.modules['pupydroid.vibrator'].vibrate(pattern)


# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="AndroidVibrate"

@config(compat="android", cat="troll", tags=["vibrator"])
class AndroidVibrate(PupyModule):
    """ activate the phone/tablet vibrator :) """

    dependencies=['pupydroid.vibrator']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="vibrator", description=cls.__doc__)

    def run(self, args):
        #Each element then alternates between vibrate, sleep, vibrate, sleep...
        pattern=[1000,1000,1000,1000,1000,1000,1000,1000]

        self.client.conn.modules['pupydroid.vibrator'].vibrate(pattern)

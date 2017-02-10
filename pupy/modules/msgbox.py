# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="MsgBoxPopup"

@config(cat="troll", tags=["message","popup"])
class MsgBoxPopup(PupyModule):
    """ Pop up a custom message box """
    dependencies = {
        'windows': [ 'pupwinutils.msgbox' ],
        'linux': [ 'notify' ],
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="msgbox", description=self.__doc__)
        self.arg_parser.add_argument('--title', help='msgbox title')
        self.arg_parser.add_argument('text', help='text to print in the msgbox :)')

    def run(self, args):
        if self.client.is_windows():
            self.client.conn.modules['pupwinutils.msgbox'].MessageBox(args.text, args.title)
        elif self.client.is_linux():
            self.client.conn.modules['notify'].notification(args.text, args.title)
        elif self.client.is_darwin():
            cmd = 'osascript -e \'tell app "Finder" to display dialog "%s"\'' % args.text
            self.client.conn.modules.os.popen(cmd)

        self.log("message box popped !")

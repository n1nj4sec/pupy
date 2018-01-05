#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import os, os.path, time, threading, random, string
import logging
import tornado.ioloop
import tornado.web
from tornado.options import define, options, parse_command_line
import tornado.template
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
import json

from tornado.websocket import WebSocketHandler
from tornado.web import RequestHandler

__all__=['RequestHandler', 'WebSocketHandler', 'tornado']

ROOT=os.path.join(os.path.dirname(__file__), "..")

class PupyWebServer(object):
    def __init__(self, pupsrv, config):
        self.pupsrv=pupsrv
        self.config=config
        self.clients={}
        self.app=None
        self.port=9000
        self.templates=None

    def start(self):

        self.app = tornado.web.Application([
            (r'/', IndexHandler),
            #(r'/ws', WebSocketHandler, {'websrv' : self}),
            (r'/(.*)', tornado.web.StaticFileHandler, {'path': os.path.join(ROOT, 'webstatic/')}),
        ], debug=True, template_path=os.path.join(ROOT, "webstatic"))

        self.app.listen(self.port, address='127.0.0.1')

        self.ioloop=tornado.ioloop.IOLoop.instance()

        t=threading.Thread(target=self.ioloop.start)
        t.daemon=True
        t.start()

    def stop():
        self.ioloop.stop()

    def start_webplugin(self, web_handlers):
        random_path="/"+''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))
        for tab in web_handlers:
            if len(tab)==2:
                path, handler = tab
                kwargs = {}
            else:
                path, handler, kwargs = tab
            logging.warning("adding handler http://127.0.0.1:9000%s"%(random_path+path))
            self.app.add_handlers(".*", [ (random_path+path, handler, kwargs) ])
        return "http://127.0.0.1:%s%s"%(self.port, random_path)

class IndexHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self):
        self.render("index.html")

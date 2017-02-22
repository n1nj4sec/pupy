#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2016, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import tornado.ioloop
import tornado.web
import tornado.websocket
import os, os.path, time
from tornado.options import define, options, parse_command_line
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
import json
from pupylib.PupyCmd import PupyCmd

class PupyWebServer(object):
    def __init__(self, pupsrv, configFile="pupy.conf"):
        self.pupsrv=pupsrv
        self.pupsrv.register_handler(self)
        self.config=configparser.ConfigParser()
        self.config.read(configFile)
        self.clients={}
        self.port=9000 # need to change the templates if this is customizable

    def start(self):
        app = tornado.web.Application([
            (r'/', IndexHandler),
            (r'/ws', WebSocketHandler, {'websrv' : self}),
            (r'/(.*)', tornado.web.StaticFileHandler, {'path': os.path.join(os.path.dirname(__file__),'static')}),
        ])

        app.listen(self.port, address='127.0.0.1')
        print "[+] Starting webserver on http://127.0.0.1:%s"%self.port
        tornado.ioloop.IOLoop.instance().start()
        
    def display_srvinfo(self, msg):
        for i, x in self.clients.iteritems():
            x.write_message(json.dumps({'srvinfo':msg}))



class IndexHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self):
        self.render("static/index.html")

class WebSocketHandler(tornado.websocket.WebSocketHandler):
    def initialize(self, websrv):
        self.websrv=websrv

    def open(self, *args):
        self.id = self.get_argument("Id")
        self.stream.set_nodelay(True)
        self.websrv.clients[self.id] = self

    def on_message(self, message):        
        print "Received a message : %s" % (message)
        #self.write_message("connected clients :")
        if message=="sessions":
            client_list=self.websrv.pupsrv.get_clients_list()
            msg=json.dumps({'srvinfo' : PupyCmd.table_format([x.desc for x in client_list])})
            print "sending msg: %s"%msg
            self.write_message(msg)
        
    def on_close(self):
        if self.id in self.websrv.clients:
            del self.websrv.clients[self.id]



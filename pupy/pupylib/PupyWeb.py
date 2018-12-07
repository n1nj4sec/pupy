#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

__all__=['RequestHandler', 'WebSocketHandler']

import threading
import random
import string
import tornado.ioloop
import tornado.web
import tornado.template

from os import path, unlink
from ssl import create_default_context

from tornado.websocket import WebSocketHandler as TornadoWebSocketHandler
from tornado.web import RequestHandler as TornadoRequestHandler
from tornado.web import StaticFileHandler as TornadoStaticFileHandler
from tornado.web import ErrorHandler as TornadoErrorHandler
from tornado.web import Application as TornadoApplication

from pupylib.PupyOutput import Error
from pupylib.PupyOutput import Success

from socket import getaddrinfo
from socket import error as socket_error

LOCAL_IPS = ('127.0.0.1', '::1')

SERVER_HEADER = 'nginx/1.13.8'

def setup_local_ips(klass, kwargs):
    config = kwargs.pop('config', None)

    setattr(klass, 'config', config)
    setattr(klass, 'local_ips', LOCAL_IPS)

    if not config:
        return

    local_ips_cnf = klass.config.get('webserver', 'local_ips')
    if not local_ips_cnf:
        return

    local_ips_set = set()
    for item in local_ips_cnf.split(','):
        item = item.strip()
        try:
            gai = getaddrinfo(item, None)
        except socket_error:
            continue

        for result in gai:
            for addr in result[4]:
                local_ips_set.add(addr)

    klass.local_ips = tuple(local_ips_set)


class ErrorHandler(TornadoErrorHandler):
    def initialize(self, **kwargs):
        setup_local_ips(self, kwargs)
        super(ErrorHandler, self).initialize(**kwargs)

    def set_default_headers(self):
        self.set_header('Server', SERVER_HEADER)

class WebSocketHandler(TornadoWebSocketHandler):
    def initialize(self, **kwargs):
        setup_local_ips(self, kwargs)
        super(WebSocketHandler, self).initialize(**kwargs)

    def set_default_headers(self):
        self.set_header('Server', SERVER_HEADER)

    def prepare(self, *args, **kwargs):
        if self.request.remote_ip not in self.local_ips:
            self.set_status(403)

            log_msg = 'Connection allowed only from local addresses'
            self.finish(log_msg)
            return

        super(WebSocketHandler, self).prepare(*args, **kwargs)

class RequestHandler(TornadoRequestHandler):
    def initialize(self, **kwargs):
        setup_local_ips(self, kwargs)
        super(RequestHandler, self).initialize(**kwargs)

    def set_default_headers(self):
        self.set_header('Server', SERVER_HEADER)

    def prepare(self, *args, **kwargs):
        if self.request.remote_ip not in self.local_ips:
            self.set_status(403)
            log_msg = 'Connection allowed only from local addresses'
            self.finish(log_msg)
            return

        super(RequestHandler, self).prepare(*args, **kwargs)

class StaticTextHandler(TornadoRequestHandler):
    def initialize(self, **kwargs):
        self.content = kwargs.pop('content')
        setup_local_ips(self, kwargs)

        super(StaticTextHandler, self).initialize(**kwargs)

    def set_default_headers(self):
        self.set_header('Server', SERVER_HEADER)

    @tornado.web.asynchronous
    def get(self):
        self.finish(self.content)

class PayloadsHandler(TornadoStaticFileHandler):
    def set_default_headers(self):
        self.set_header('Server', SERVER_HEADER)

    def initialize(self, **kwargs):
        self.mappings = kwargs.pop('mappings', {})
        self.templates = kwargs.pop('templates', {})
        self.mapped = False

        setup_local_ips(self, kwargs)

        super(PayloadsHandler, self).initialize(**kwargs)

    def get_absolute_path(self, root, filepath):
        if filepath in self.mappings:
            mapped_path = self.mappings[filepath]

            if path.isfile(mapped_path):
                self.mapped = True
                return path.abspath(mapped_path)

            elif path.isfile(path.join(root, self.mappings)):
                self.mapped = True
                return path.abspath(
                    path.join(root, self.mappings))

        self.mapped = False
        return super(PayloadsHandler, self).get_absolute_path(root, filepath)

    def validate_absolute_path(self, root, absolute_path):
        if self.mapped:
            return absolute_path

        return super(PayloadsHandler, self).get_absolute_path(root, absolute_path)

class IndexHandler(tornado.web.RequestHandler):
    def initialize(self, **kwargs):
        setup_local_ips(self, kwargs)
        super(IndexHandler, self).initialize(**kwargs)

    def set_default_headers(self):
        self.set_header('Server', SERVER_HEADER)

    @tornado.web.asynchronous
    def get(self):
        if self.request.remote_ip in LOCAL_IPS:
            self.render("index.html")
        else:
            self.render("nginx_index.html")

class PupyWebServer(object):
    def __init__(self, pupsrv, config):
        self.pupsrv = pupsrv
        self.config = config
        self.clients = {}
        self.mappings = {}

        self.ssl = False

        self.wwwroot = self.config.get(
            'webserver', 'static_webroot_uri', None) or \
            self.random_path()

        self.preserve_payloads = self.config.getboolean(
            'webserver', 'preserve_payloads')

        self.root = self.config.get_folder('wwwroot')

        self.app = None

        self._thread = None
        self._ioloop = None

        self.listen = config.get('webserver', 'listen')
        if ':' in self.listen:
            hostname, port = self.listen.rsplit(':', 1)
            port = int(port)
            self.hostname, self.port = hostname, port
        else:
            self.hostname = self.listen
            self.port = 9000

        self.served_files = set()
        self.aliases = {}
        self.show_requests = self.config.getboolean('webserver', 'log')

    def log(self, handler):
        if not self.show_requests:
            return

        message = 'Web: '

        if handler.request.uri in self.aliases:
            message += '({}) '.format(self.aliases[handler.request.uri])

        message += handler._request_summary()

        if handler.get_status() < 400:
            self.pupsrv.info(Success(message))
        else:
            self.pupsrv.info(Error(message))

    def start(self):
        webstatic = self.config.get_folder('webstatic', create=False)
        cert = self.config.get('webserver', 'cert', None)
        key = self.config.get('webserver', 'key', None)

        self.app = TornadoApplication(
            [
             (r'/', IndexHandler),
             (self.wwwroot + '/(.*)', PayloadsHandler, {
                 'path': self.root,
                 'mappings': self.mappings,
             }),
             (r'/static/(.*)', TornadoStaticFileHandler, {
                 'path': webstatic
             }),
            ],
            debug=False, template_path=webstatic,
            log_function=self.log,
            default_handler_class=ErrorHandler,
            default_handler_args={
                'status_code':404,
            }
        )

        ssl_options = None

        if key and cert:
            ssl_options = create_default_context(
                certfile=cert, keyfile=key, server_side=True)
            self.ssl = True

        self.app.listen(
            self.port,
            address=self.hostname,
            ssl_options=ssl_options)

        self._ioloop = tornado.ioloop.IOLoop.instance()

        self._thread = threading.Thread(target=self._ioloop.start)
        self._thread.daemon = True
        self._thread.start()

        self._registered = {}

    def stop(self):
        self._ioloop.stop()
        self._ioloop = None
        self._thread = None

        for (_, _, cleanup) in self._registered.itervalues():
            if cleanup:
                cleanup()

        self.mappings = {}
        self.aliases = {}

        if self.preserve_payloads:
            return

        for filepath in self.served_files:
            if path.isfile(filepath):
                unlink(filepath)

    def get_random_path_at_webroot(self):
        while True:
            filename = ''.join(random.choice(
                string.ascii_uppercase + \
                string.ascii_lowercase + \
                string.digits) for _ in range(10))

            filepath = path.join(self.root, filename)
            if not path.isfile(filepath):
                return filepath, filename

    def random_path(self):
        return '/'+''.join(
            random.choice(
                string.ascii_uppercase + \
                string.ascii_lowercase + \
                string.digits) for _ in range(10))

    def register_mapping(self, name):
        name = self.random_path()
        self.mappings[name] = path
        if name in self.mappings:
            del self.mappings[name]

    def is_registered(self, name):
        return self._registered.get(name, (None, None, None))[0]

    def serve_content(self, content, alias=None, as_file=True):
        uri = None

        if as_file:
            filepath, filename = self.get_random_path_at_webroot()
            try:
                with open(filepath, 'w') as out:
                    out.write(content)
                self.served_files.add(filepath)
            except:
                if path.isfile(filepath):
                    path.unlink(filepath)

                raise

            uri = self.wwwroot + '/' + filename
        else:
            uri = self.random_path()
            self.app.add_handlers('.*', [(
                uri, StaticTextHandler, {
                    'content': content
                })])

        if alias:
            self.aliases[uri] = alias

        return uri

    def start_webplugin(self, name, web_handlers, cleanup=None):
        random_path = self.random_path()

        if name in self._registered:
            random_path, _, _ = self._registered[name]
            return self.port, random_path

        klasses = []

        for tab in web_handlers:
            if len(tab)==2:
                uri_path, handler = tab
                kwargs = {}
            else:
                uri_path, handler, kwargs = tab

            ends_with_slash = uri_path.endswith('/')
            uri_path = '/'.join(x for x in [random_path] + uri_path.split('/') if x)
            if ends_with_slash:
                uri_path += '/'

            klasses.append(handler)

            if issubclass(handler, (
                ErrorHandler, WebSocketHandler,
                RequestHandler, StaticTextHandler, PayloadsHandler, IndexHandler)):

                kwargs['config'] = self.config

            self.app.add_handlers(".*", [(uri_path, handler, kwargs)])
            self.pupsrv.info('Register webhook for {} at {}'.format(name, uri_path))

        self._registered[name] = random_path, klasses, cleanup

        return self.port, random_path

    def stop_webplugin(self, name):

        if name not in self._registered:
            return

        self.pupsrv.info('Unregister webhook for {}'.format(name))

        random_path, klasses, cleanup = self._registered[name]
        removed = False

        to_remove = []
        for rule in self.app.wildcard_router.rules:
            if rule.target in klasses:
                to_remove.append(rule)
                removed = True
            elif rule.matcher.regex.pattern.startswith(random_path):
                to_remove.append(rule)
                removed = True

        for rule in to_remove:
            self.app.wildcard_router.rules.remove(rule)

        to_remove = []
        for rule in self.app.default_router.rules:
            if rule.target in klasses:
                to_remove.append(rule)
                removed = True
            elif rule.matcher.regex.pattern.startswith(random_path):
                to_remove.append(rule)
                removed = True

        if cleanup:
            cleanup()

        if removed:
            del self._registered[name]
        else:
            self.pupsrv.info('{} was not found [error]'.format(name))

# -*- coding: utf-8 -*-

from ..base import BasePupyTransport
from .utils import *
from http_parser.parser import HttpParser
from os import path, stat

class PupyHTTPWrapperServer(BasePupyTransport):
    path = '/index.php?d='
    allowed_methods = ( 'GET' )
    root = '/tmp'
    headers = {
        'Content-Type' : 'text/html; charset=utf-8',
        'Server' : 'Apache',
        'Connection': 'close',
    }

    def __init__(self, *args, **kwargs):
        super(PupyHTTPWrapperServer, self).__init__(*args, **kwargs)

        self.parser = HttpParser()
        self.is_http = None
        self.body = []

    def _http_response(self, code, status, headers=None, datasize=None, content=None):
        headers = {}
        headers.update(self.headers)

        if headers:
            headers.update(headers)

        if datasize:
            headers.update({
                'Content-Length': datasize,
                'Content-Type': 'application/octet-steram',
            })

        data = '\r\n'.join([
            'HTTP/1.1 {} {}'.format(code, status),
            '\r\n'.join([
                '{}: {}'.format(key, value) for key,value in headers.iteritems()
            ])
        ]) + '\r\n\r\n'

        self.downstream.write(data)

    def _handle_file(self, filepath):
        try:
            with open(filepath) as infile:
                size = stat(filepath).st_size
                self._http_response(200, 'OK', datasize=size)

                while True:
                    data = infile.read(65535)
                    if data:
                        self.downstream.write(data)
                    else:
                        break

        except Exception, e:
            self._http_response(404, 'Not found', 'Not found')

    def _handle_not_found(self):
        self._http_response(404, 'Not found', 'Not found')

    def _handle_http(self, data):
        self.parser.execute(data, len(data))

        if self.parser.is_headers_complete():
            try:
                if not self.parser.get_method() in ('GET'):
                    self._http_response(405, 'Method Not Allowed')
                else:
                    urlpath = self.parser.get_path()
                    urlpath = path.sep.join([
                        x.strip() for x in urlpath.split('/') if (
                            x and not str(x) in ('.', '..')
                        )
                    ])

                    filepath = path.join(self.root, urlpath)
                    if path.exists(filepath):
                        self._handle_file(filepath)
                    else:
                        self._handle_not_found()
            finally:
                self.close()

    def downstream_recv(self, data):
        payload = data.read()

        if self.is_http is None:
            self.is_http = payload.startswith(
                ('GET', 'POST', 'OPTIONS', 'HEAD', 'PUT', 'DELETE')
            ) and not payload.startswith(self.path)

        if self.is_http:
            self._handle_http(payload)
        else:
            self.upstream.write(payload)

    def upstream_recv(self, data):
        payload = data.read()
        if payload:
            self.downstream.write(payload)

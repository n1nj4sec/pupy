# -*- coding: utf-8 -*-

__all__ = ['PupyHTTPWrapperServer']

from ..base import BasePupyTransport, ReleaseChainedTransport

from http_parser.parser import HttpParser
from os import path, stat
from network.lib.buffer import Buffer
from network.lib import getLogger

logger = getLogger('httpwrap')

class PupyHTTPWrapperServer(BasePupyTransport):
    path = '/index.php?d='
    allowed_methods = ('GET')
    server = None
    headers = {
        'Content-Type': 'text/html; charset=utf-8',
        'Server': 'Apache',
        'Connection': 'close',
    }

    __slots__ = (
        'parser', 'is_http',
        'body', 'downstream_buffer',
        'well_known', 'omit', 'probe_len'
    )

    def __init__(self, *args, **kwargs):
        super(PupyHTTPWrapperServer, self).__init__(*args, **kwargs)

        self.parser = HttpParser()
        self.is_http = None
        self.body = []
        self.downstream_buffer = Buffer()

        self.well_known = ('GET', 'POST', 'OPTIONS', 'HEAD', 'PUT', 'DELETE')
        self.omit = tuple(
            '{} {}'.format(x, y) for x in self.well_known for y in (
                self.path, '/ws/', 'ws/'))
        self.probe_len = max(len(x) for x in self.omit)

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

        except:
            self._http_response(404, 'Not found', 'Not found')

    def _handle_not_found(self):
        self._http_response(404, 'Not found', 'Not found')

    def _handle_http(self, data):
        self.parser.execute(data, len(data))

        if self.parser.is_headers_complete():
            try:
                if not self.parser.get_method() in self.allowed_methods:
                    self._http_response(405, 'Method Not Allowed')

                else:
                    urlpath = self.parser.get_path()
                    urlpath = [
                        x.strip() for x in urlpath.split('/') if (
                            x and not str(x) in ('.', '..')
                        )
                    ]

                    root = self.server.config.get_folder('wwwroot')
                    secret = self.server.config.getboolean('httpd', 'secret')
                    log = self.server.config.getboolean('httpd', 'log')

                    if secret:
                        wwwsecret = self.server.config.get('randoms', 'wwwsecret', random=5)
                        if not (urlpath and urlpath[0] == wwwsecret):
                            self._handle_not_found()
                            if log:
                                self.server.handler.display_error('{}: GET {} | SECRET = {}'.format(
                                    '{}:{}'.format(*self.downstream.transport.peer[:2]), urlpath, wwwsecret))
                            return

                        urlpath = urlpath[1:]

                    urlpath = path.sep.join([
                        self.server.config.get('randoms', x, new=False) or x for x in urlpath
                    ])

                    if not urlpath:
                        urlpath = 'index.html'

                    filepath = path.join(root, urlpath)

                    if path.exists(filepath):
                        self._handle_file(filepath)
                        if log:
                            self.server.handler.display_success('{}: GET {}'.format(
                                '{}:{}'.format(*self.downstream.transport.peer[:2]), urlpath))

                    else:
                        self._handle_not_found()
                        if log:
                            self.server.handler.display_error('{}: GET {}'.format(
                                '{}:{}'.format(*self.downstream.transport.peer[:2]), urlpath))

            except Exception, e:
                print "Exception: {}".format(e)

            finally:
                self.close()

    def downstream_recv(self, data):
        header = data.peek(self.probe_len)

        if __debug__:
            logger.debug('Recv: len=%d // header = %s', len(data), header)

        if self.server and self.is_http is None:
            self.is_http = header.startswith(self.well_known) and \
              not header.startswith(self.omit)

            if __debug__:
                logger.debug('Http: %s', self.is_http)

        if self.is_http:
            self._handle_http(data.read())
        else:
            if __debug__:
                logger.debug('Write to upstream: len=%d, handler=%s',
                    len(data), self.upstream.on_write_f)

            data.write_to(self.upstream)

            if self.downstream_buffer:
                if __debug__:
                    logger.debug('Flush buffer to downstream: len=%d, handler=%s',
                        len(self.downstream_buffer), self.downstream.on_write_f)

                self.downstream_buffer.write_to(self.downstream)

            if __debug__:
                logger.debug('Release transport')

            raise ReleaseChainedTransport()

    def upstream_recv(self, data):
        if __debug__:
            logger.debug('Send intent: len=%d', len(data))

        if self.is_http is None:
            data.write_to(self.downstream_buffer)

            if __debug__:
                logger.debug('HTTP? Append to pending buffer: total len=%d',
                    len(self.downstream_buffer))

        elif not self.is_http:
            if __debug__:
                logger.debug('Non-HTTP: Direct pass (handler=%s)',
                    self.downstream.on_write_f)

            if self.downstream_buffer:
                self.downstream_buffer.write_to(self.downstream)

            data.write_to(self.downstream)
        else:
            if __debug__:
                logger.debug('HTTP: Omit data')

            pass

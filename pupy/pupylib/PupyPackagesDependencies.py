#!/usr/bin/env python
# -*- coding: UTF8 -*-

LOAD_PACKAGE=1
LOAD_DLL=2
EXEC=3

# dependencies to load for each modules
packages_dependencies={

	"pupwinutils.memexec" : [
		(LOAD_PACKAGE, "pupymemexec"),
	],
	"scapy" : [
		(LOAD_PACKAGE, "pcap"),
		(LOAD_PACKAGE, "dnet"),
		(EXEC, "import socket\nsocket.IPPROTO_IPIP=4\nsocket.IPPROTO_AH=51\nsocket.IPPROTO_ESP=50\n") #hotpatching socket module missing some constants on windows
	],

}

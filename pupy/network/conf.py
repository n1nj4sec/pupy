# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import os, sys, logging, pkgutil
from .lib.launchers.connect import ConnectLauncher
from .lib.launchers.auto_proxy import AutoProxyLauncher
from .lib.launchers.bind import BindLauncher

transports={}
launchers={}
if "network.transports" not in sys.modules:
    import transports as trlib
    for loader, module_name, is_pkg in pkgutil.iter_modules(trlib.__path__):
        try:
            loader2=pkgutil.get_loader("network.transports."+module_name+".conf")
            confmodule=loader2.load_module("conf")
            if not hasattr(confmodule,"TransportConf"):
                logging.error("No class TransportConf in transport network.transports.%s"%module_name)
                continue
            t=confmodule.TransportConf
            if t.name is None:
                logging.warning("Transport %s has no defined attribute name. using package name as a fallback"%module_name)
                t.name=module_name

            transports[t.name]=t
            logging.debug("[+] transport %s loaded"%t.name)
        except Exception as e:
            logging.warning("Could not load transport %s : %s. Transport disabled"%(module_name,e))


launchers["connect"]=ConnectLauncher
launchers["auto_proxy"]=AutoProxyLauncher
launchers["bind"]=BindLauncher


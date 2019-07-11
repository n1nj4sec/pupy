# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root
# of the project for the detailed licence terms

__all__ = (
    'load_network_modules', 'transports', 'launchers'
)


import logging
import importlib
import pkgutil

import transports as trlib

transports = {}
launchers = {}


def add_transport(module_name):
    try:
        confmodule = importlib.import_module(
            'network.transports.{}.conf'.format(module_name))

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


def load_network_modules():
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

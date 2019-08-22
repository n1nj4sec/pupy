# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at
# the root of the project for the detailed licence terms

import shlex
import sys

from collections import namedtuple

TransportInfo = namedtuple(
    'TransportInfo', [
        'host', 'port', 'transport',
        'transport_args', 'client_args'
    ])

HostInfo = namedtuple(
    'HostInfo', [
        'host', 'port'
    ])


class TransportException(Exception):
    pass


def error(message, exit=True):
    if exit:
        raise SystemExit(message)
    else:
        raise TransportException(message)


def parse_transports_args(args, exit=True):
    if type(args) not in (str, unicode):
        args = ' '.join(args)

    result = {}

    for value in shlex.split(args):
        if '=' not in value:
            error(
                'Transport arguments must be in format '
                'NAME=VALUE or "NAME=value with spaces"',
                exit=exit)

        key, value = value.split('=', 1)

        result[key.lower()] = value

    return result


def parse_host(host, default_port=443):
    port = default_port

    if ':' in host:
        host, port = host.rsplit(':', 1)
        port = int(port)

    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]

    return HostInfo(host, port)


def create_client_transport_info_for_addr(
    transport_name,
        hostinfo, opt_args={}, bind_payload=None, exit=True):

    host, port = hostinfo

    if transport_name not in sys.pupy_transports:
        error('Unregistered transport {}'.format(transport_name), exit=exit)

    transport_klass = sys.pupy_transports[transport_name]
    transport = transport_klass(bind_payload=bind_payload)

    transport_args = transport.client_transport_kwargs
    client_args = transport.client_kwargs

    if 'host' not in opt_args:
        transport_args['host'] = '{}{}'.format(
            host, ':{}'.format(port) if port != 80 else ''
        )

    for key, value in opt_args.iteritems():
        if key in client_args:
            client_args[key] = value
        elif key in transport_args:
            transport_args[key] = value
        else:
            error('Unknown transport argument: {}'.format(key), exit=exit)

    return TransportInfo(host, port, transport, transport_args, client_args)


__all__ = (
    TransportInfo, TransportException,
    create_client_transport_info_for_addr,
    parse_host, parse_transports_args, HostInfo
)

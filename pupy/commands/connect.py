# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import pupy.network.conf as conf

launcher = conf.launchers['connect'](
    connect_on_bind_payload=True
)

usage = 'Connect to the bind payload'
parser = launcher.arg_parser


def do(server, handler, config, args):
    launcher.args = args
    launcher.parse_args(None)
    server.connect_on_client(launcher)

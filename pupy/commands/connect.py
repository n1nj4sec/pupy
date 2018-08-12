# -*- encoding: utf-8 -*-

import network.conf

launcher = network.conf.launchers['connect'](
    connect_on_bind_payload=True
)

usage = 'Connect to the bind payload'
parser = launcher.arg_parser

def do(server, handler, config, args):
    launcher.args = args
    server.connect_on_client(launcher)

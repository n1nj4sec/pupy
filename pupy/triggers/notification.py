# -*- encoding: utf-8 -*-

IGNORED_EVENTS = (
    'start', 'exit', 'connect', 'disconnect', 'job completed'
)

import datetime

def execute(event_name, client, server, handler, config, **kwargs):
    if event_name in IGNORED_EVENTS:
        return

    client_id = ''
    if 'id' in kwargs:
        client_id = 'client {}'.format(kwargs['id'])
    elif 'sid' in kwargs:
        client_id = 'session {:08x}'.format(kwargs['sid'])
    elif 'node' in kwargs:
        client_id = 'node {:12x}'.format(kwargs['node'])

    server.info('Event ({}): {} ({})'.format(
        datetime.datetime.now(), event_name, client_id))

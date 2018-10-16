# -*- coding: utf-8 -*-

def execute(event_name, client, server, handler, config, **kwargs):
    server.info(
        'Event: {}, client={}, server={}, handler={}, config={}, kwargs={}'.format(
            event_name, client, server, handler, config, kwargs))

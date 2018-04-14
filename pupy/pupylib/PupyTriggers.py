# -*- coding: utf-8 -*-

import datetime
import logging

from .PupyConfig import Error, NoSectionError

logger = logging.getLogger('triggers')

ON_CONNECT = 0
ON_DISCONNECT = 1
ON_DNSCNC_SESSION = 2
ON_DNSCNC_SESSION_LOST = 3
ON_EXIT = 255

def event_to_config_section(event):
    return {
        ON_EXIT: 'on_exit',
        ON_CONNECT: 'on_connect',
        ON_DISCONNECT: 'on_disconnect',
        ON_DNSCNC_SESSION: 'on_dnscnc_session',
        ON_DNSCNC_SESSION_LOST: 'on_dnscnc_session_lost'
    }.get(event)

def event_to_string(event):
    return {
        ON_EXIT: 'exit',
        ON_CONNECT: 'connect',
        ON_DISCONNECT: 'disconnect',
        ON_DNSCNC_SESSION: 'dnscnc session',
        ON_DNSCNC_SESSION_LOST: 'dnscnc session lost'
    }.get(event)

def substitute_info(client, info):
    return cmdline.replace(cmdline.format(**info))

def _do(eventid, action, handler, client_filter):
    event = event_to_string(eventid)
    handler.inject(
        action, client_filter if eventid in (
            ON_CONNECT, ON_DISCONNECT
        ) else None,
        'Action for event "{}" apply to <{}>: {}'.format(
            event, client_filter, action))

def _event(eventid, client, handler, config):
    section = event_to_config_section(eventid)

    for client_filter, action in config.items(section):
        on_self = False

        if client_filter.lower() in ('this', 'self', 'current', '@'):
            on_self = True

            if eventid in ( ON_CONNECT, ON_DISCONNECT ):
                client_filter = client.desc['id']
            else:
                client_filter = client_filter.lower()

        if action.startswith('include:'):
            _, included_section = action.split(':', 1)
            try:
                for action_name, action in config.items(included_section):
                    if eventid in ( ON_DNSCNC_SESSION, ON_DNSCNC_SESSION_LOST ):
                        action = action.replace('%c', '{:08x}'.format(client.spi))
                        node = '{:012x}'.format(client.system_info['node'])
                        if client_filter not in ('*', 'any', node):
                            continue

                    _do(eventid, action, handler, client_filter)
            except NoSectionError:
                pass

        else:
            if eventid in ( ON_DNSCNC_SESSION, ON_DNSCNC_SESSION_LOST ):
                action = action.replace('%c', '{:08x}'.format(client.spi))
                node = '{:012x}'.format(client.system_info['node'])
                if client_filter not in ('*', 'any', node):
                    continue

            _do(eventid, action, handler, client_filter)

def event(eventid, client, handler, config):
    try:
        _event(eventid, client, handler, config)

    except NoSectionError:
        pass

    except Error, e:
        logger.error(e)

    except Exception, e:
        logger.exception(e)

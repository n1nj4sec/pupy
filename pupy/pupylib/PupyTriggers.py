# -*- coding: utf-8 -*-

import datetime
import logging

from .PupyConfig import Error, NoSectionError

from . import getLogger
logger = getLogger('triggers')

ON_CONNECT = 0
ON_DISCONNECT = 1
ON_DNSCNC_SESSION = 2
ON_DNSCNC_SESSION_LOST = 3
ON_START = 254
ON_EXIT = 255

def event_to_config_section(event):
    return {
        ON_START: 'on_start',
        ON_EXIT: 'on_exit',
        ON_CONNECT: 'on_connect',
        ON_DISCONNECT: 'on_disconnect',
        ON_DNSCNC_SESSION: 'on_dnscnc_session',
        ON_DNSCNC_SESSION_LOST: 'on_dnscnc_session_lost'
    }.get(event)

def event_to_string(event):
    return {
        ON_START: 'start',
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

def _event(eventid, client, server, handler, config):
    section = event_to_config_section(eventid)
    actions = config.items(section)

    for client_filter, action in actions:
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
                for nested in config.items(included_section):
                    actions.append(nested)
            except NoSectionError:
                pass

            continue

        node = None

        if eventid in ( ON_DNSCNC_SESSION, ON_DNSCNC_SESSION_LOST ):
            action = action.replace('%c', '{:08x}'.format(client.spi))
            node = '{:012x}'.format(client.system_info['node'])

        elif eventid in ( ON_CONNECT, ON_DISCONNECT ):
            node = client.desc['node']

            try:
                action = action.format(**client.desc)
            except (ValueError, KeyError) as e:
                logger.error('Invalid action format ({}): {}'.format(action, e))

        criterias = ['*', 'any']

        if node:
            criterias.append(node)
            criterias.extend(list(config.tags(node)))

        if client_filter not in criterias and not client_filter.startswith(('*', 'any')) and \
            client not in server.get_clients(client_filter):

            logger.debug('Incompatible event: eventid={} criterias={} client_filter={} action={}'.format(
                event_to_string(eventid), criterias, client_filter, action))

            continue

        logger.debug('Compatible event: eventid={} criterias={} client_filter={} action={}'.format(
            event_to_string(eventid), criterias, client_filter, action))

        _do(eventid, action, handler, client_filter)

def event(eventid, client, server, handler, config):
    try:
        _event(eventid, client, server, handler, config)

    except NoSectionError:
        pass

    except Error, e:
        logger.error(e)

    except Exception, e:
        logger.exception(e)

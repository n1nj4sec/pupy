# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from time import sleep
from socket import SOCK_DGRAM, SOCK_STREAM

from psutil import net_connections, Process, Error

import pupy


INTERVAL = 1


class NetMon(pupy.Task):
    results_type = list

    __slots__ = (
        'known_listeners_tcp', 'known_listeners_udp',
        'known_egress_tcp', 'known_egress_udp',
        'known_ingress_tcp', 'known_ingress_udp',
        'pending_udp_listeners'
    )

    def __init__(self, *args, **kwargs):
        super(NetMon, self).__init__(*args, **kwargs)

        self.known_listeners_tcp = set()
        self.known_egress_tcp = set()
        self.known_ingress_tcp = set()
        self.known_listeners_udp = set()
        self.known_egress_udp = set()
        self.known_ingress_udp = set()
        self.pending_udp_listeners = dict()

    def _update(self, connections):
        listeners_tcp = set()
        listeners_udp = set()

        ingress_tcp = set()
        ingress_udp = set()

        egress_tcp = set()
        egress_udp = set()

        # Register listeners first
        for connection in connections:
            if connection.raddr:
                continue

            program = ''

            if connection.pid:
                try:
                    process = Process(connection.pid)
                    program = process.exe()
                except Error:
                    program = 'pid={}'.format(connection.pid)

            listeners = None

            if connection.type == SOCK_DGRAM:
                listeners = listeners_udp
            elif connection.type == SOCK_STREAM and connection.status == 'LISTEN':
                listeners = listeners_tcp
            else:
                continue

            listeners.add((program, connection.laddr.ip, connection.laddr.port))

        new_listeners_tcp = listeners_tcp - self.known_listeners_tcp
        new_listeners_udp = listeners_udp - self.known_listeners_udp

        for new_listener_udp in new_listeners_udp:
            if new_listener_udp not in self.pending_udp_listeners:
                self.pending_udp_listeners[new_listener_udp] = 1
            else:
                self.pending_udp_listeners[new_listener_udp] += 1

        for old_listener_udp in list(self.pending_udp_listeners):
            if old_listener_udp not in new_listener_udp:
                del self.pending_udp_listeners[old_listener_udp]

        new_listeners_udp = set(
            new_listener_udp for new_listener_udp, cnt in
            self.pending_udp_listeners.items() if
            cnt > 16
        )

        for new_listener_udp in new_listeners_udp:
            del self.pending_udp_listeners[new_listener_udp]

        self.known_listeners_tcp.update(listeners_tcp)
        self.known_listeners_udp.update(new_listeners_udp)

        known_listeners_udp = set(
            (ip, port) for _, ip, port in self.known_listeners_udp
        )

        known_listeners_tcp = set(
            (ip, port) for _, ip, port in self.known_listeners_tcp
        )

        # Now update ingress/egress connections
        for connection in connections:
            if not connection.raddr:
                continue

            program = ''

            if connection.pid:
                try:
                    process = Process(connection.pid)
                    program = process.exe()
                except Error:
                    program = 'pid={}'.format(connection.pid)

            remote_ip = connection.raddr.ip
            remote_tuple = connection.raddr.ip, connection.raddr.port
            local = connection.laddr.ip, connection.laddr.port

            connlist = None
            connitem = None

            if connection.type == SOCK_DGRAM:
                if any(
                    candidate in known_listeners_udp for candidate in (
                        local, ('::', local[1]), ('0.0.0.0', local[1]),
                        ('127.0.0.1', local[1]), '::ffff:127.0.0.1', local[1])):
                    connlist = ingress_udp
                    connitem = program, local, remote_ip
                else:
                    connlist = egress_udp
                    connitem = program, remote_tuple

            elif connection.type == SOCK_STREAM:
                if any(
                    candidate in known_listeners_tcp for candidate in (
                        local, ('::', local[1]), ('0.0.0.0', local[1]),
                        ('127.0.0.1', local[1]), '::ffff:127.0.0.1', local[1])):
                    connlist = ingress_tcp
                    connitem = program, local, remote_ip
                else:
                    connlist = egress_tcp
                    connitem = program, remote_tuple

            else:
                continue

            connlist.add(connitem)

        new_ingress_udp = ingress_udp - self.known_ingress_udp
        new_ingress_tcp = ingress_tcp - self.known_ingress_tcp

        new_egress_udp = egress_udp - self.known_egress_udp
        new_egress_tcp = egress_tcp - self.known_egress_tcp

        self.known_ingress_udp.update(ingress_udp)
        self.known_ingress_tcp.update(ingress_tcp)

        self.known_egress_udp.update(egress_udp)
        self.known_egress_tcp.update(egress_tcp)

        new_objects = tuple(
            tuple(x) for x in (
                new_listeners_tcp, new_listeners_udp,
                new_ingress_tcp, new_ingress_udp,
                new_egress_tcp, new_egress_udp)
        )

        if not any(x for x in new_objects):
            return

        self.append(new_objects)

    def task(self):
        while self.active:
            connections = net_connections(kind='inet')
            self._update(connections)
            sleep(INTERVAL)


def netmon_start(event_id=None):
    if pupy.manager.active(NetMon):
        return False

    pupy.manager.create(NetMon, event_id=event_id)
    return True


def netmon_dump():
    netmon = pupy.manager.get(NetMon)

    if netmon:
        return netmon.results


def netmon_stop():
    netmon = pupy.manager.get(NetMon)
    if netmon:
        pupy.manager.stop(NetMon)

        # Return summary table

        return [
            tuple(
                tuple(x) for x in (
                    netmon.known_listeners_tcp, netmon.known_listeners_udp,
                    netmon.known_ingress_tcp, netmon.known_ingress_udp,
                    netmon.known_egress_tcp, netmon.known_egress_udp
                )
            )
        ]

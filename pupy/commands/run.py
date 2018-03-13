# -*- encoding: utf-8 -*-

# TODO: Fix stream/interaction

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Error, Success
from argparse import REMAINDER

usage = 'Run a module on one or multiple clients'
parser = PupyArgumentParser(prog='run', description=usage)

parser.add_argument('module', metavar='<module>', help="module")
parser.add_argument('-1', '--once', default=False, action='store_true', help='Unload new deps after usage')
parser.add_argument('-o', '--output', help='save command output to file.'
                        '%%t - timestamp, %%h - host, %%m - mac, '
                        '%%c - client shortname, %%M - module name, '
                        '%%p - platform, %%u - user, %%a - ip address')
parser.add_argument(
    '-f', '--filter', metavar='<client filter>',
    help='filter to a subset of all clients. All fields available in the "info" module can be used. '
    'example: run get_info -f \'platform:win release:7 os_arch:64\'')
parser.add_argument('-b', '--background', action='store_true', help='run in background')
parser.add_argument('arguments', nargs=REMAINDER, default='', metavar='<arguments>', help='module arguments')

def do(server, handler, config, modargs):
    pj = None
    args = modargs.arguments
    selected_clients = modargs.filter or handler.default_filter

    try:
        module = server.get_module(
            server.get_module_name_from_category(modargs.module))

    except Exception as e:
        handler.display(Error(e, modargs.module))
        return

    if not module:
        handler.display(Error('Unknown module', modargs.module))
        return

    l = [None]
    if module.need_at_least_one_client:
        l = server.get_clients(selected_clients)
        if not l:
            if not server.clients:
                handler.display(Error('No clients currently connected'))
            else:
                handler.display(Error('No clients match this search!'))
            return

    modjobs = [
        x for x in server.jobs.itervalues()
        if x.pupymodules[0].get_name() == mod.get_name() and
        x.pupymodules[0].client in l
    ]

    pj = None
    interactive = False

    if module.daemon and module.unique_instance and modjobs:
        pj = modjobs[0]
    else:
        pj = server.new_job('{} {}'.format(modargs.module, ' '.join(args)))
        if len(l)==1 and not modargs.background and not module.daemon:
            ps = module(
                l[0],
                pj,
                stdout=handler.output,
                stdin=handler.input,
                log=modargs.output,
                output=handler.display,
            )
            pj.add_module(ps)
            interactive=True
        else:
            for c in l:
                ps = module(
                    c,
                    pj,
                    log=modargs.output,
                )
                pj.add_module(ps)

    try:
        pj.start(args, once=modargs.once)
    except Exception as e:
        handler.display(Error(e))
        pj.stop()

    if not module.unique_instance:
        if modargs.background or module.daemon:
            server.add_job(pj)
            handler.display(Info('Background job: {}'.format(pj)))
        else:
            error = pj.interactive_wait()
            if error and not modjobs:
                pj.stop()
    else:
        if module.daemon and not modjobs:
            server.add_job(pj)

        error = pj.interactive_wait()
        if error and not modjobs:
            pj.stop()

    if not interactive:
        summary = pj.result_summary()
        if summary is not None:
            handler.display(summary)
    else:
        if pj:
            pj.free()
            del pj

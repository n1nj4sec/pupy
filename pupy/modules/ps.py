# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain
from pupylib.utils.term import terminal_size, colorize
from modules.lib.utils.shell_exec import shell_exec
import logging

__class_name__="PsModule"

ADMINS = ('NT AUTHORITY\SYSTEM', 'root')

def gen_columns(record, colinfo):
    columns = {}

    columns['name'] = record.get('name') or '?'
    columns['cmdline'] = ' '.join([
        x for x in record['cmdline'][1:] if x.strip()
    ]) if 'cmdline' in record else ''
    columns['exe'] = record.get('exe') or '{{{}}}'.format(columns['name'])
    columns['username'] = record.get('username') or ''
    cpu = record.get('cpu_percent')
    columns['cpu_percent'] = '{:3}%'.format(int(cpu)) if cpu is not None else ' '*4
    mem = record.get('memory_percent')
    columns['memory_percent'] = '{:3}%'.format(int(mem)) if mem is not None else ' '*4

    if colinfo:
        columns['username'] = '{{:{}}}'.format(colinfo['username']).format(columns['username'])
        columns['pid'] = '{{:{}}}'.format(colinfo['pid']).format(record['pid'])
    else:
        columns['pid'] = '{}'.format(parent)

    return columns

def gen_output_line(columns, info, record, width):
    cpu = record.get('cpu_percent') or 0
    mem = record.get('memory_percent') or 0

    if record.get('self'):
        color = "green"
    elif cpu > 70 or mem > 50:
        color = "red"
    elif record.get('username') in ADMINS:
        if record.get('connections'):
            color = "magenta"
        else:
            color = "yellow"
    elif record.get('connections'):
        color = "cyan"
    elif not record.get('same_user'):
        color = "grey"
    else:
        color = None

    template = ' '.join('{{{}}}'.format(x) for x in info)
    output = template.format(**columns)
    if width:
        output = output[:width]

    if color:
        output = colorize(output, color)

    return output

def print_pstree(fout, parent, tree, data,
                      prefix='', indent='', width=80, colinfo={},
                      info=['exe', 'cmdline'], hide=[],
                      first=False):
    if parent in data:
        data[parent]['pid'] = parent
        columns = gen_columns(data[parent], colinfo)

        if ( columns['name'] in hide ) or ( columns['exe'] in hide ) or ( parent in hide ):
            return

        columns['prefix'] = prefix

        before_tree = [ x for x in info if x in ('cpu_percent', 'memory_percent', 'username') ]
        after_tree = [ x for x in info if x in ('exe', 'name', 'cmdline') ]

        outcols = [ 'pid' ] + before_tree + [ 'prefix' ] + after_tree

        fout.write(gen_output_line(columns, outcols, data[parent], width)+'\n')

    if parent not in tree:
        return

    children = tree[parent][:-1]

    for child in children:
        print_pstree(
            fout, child, tree, data,
            prefix=indent+('┌' if first else '├'), indent=indent + '│ ', width=width,
            colinfo=colinfo, info=info, hide=hide
        )

    child = tree[parent][-1]
    print_pstree(
        fout, child, tree, data,
        prefix=indent+'└', indent=indent + '  ',
        width=width, colinfo=colinfo,
        info=info, hide=hide
    )

def print_ps(fout, data, width=80, colinfo={},
                 info=['exe', 'cmdline'], hide=[]):

    outcols = [ 'pid' ] + [
        x for x in info if x in ('cpu_percent', 'memory_percent', 'username', 'exe', 'name', 'cmdline')
    ]

    for process in sorted(data):
        data[process]['pid'] = process
        columns = gen_columns(data[process], colinfo)

        if ( columns['name'] in hide ) or ( columns['exe'] in hide ) or ( process in hide ):
            continue

        fout.write(gen_output_line(columns, outcols, data[process], width)+'\n')


@config(cat="admin")
class PsModule(PupyModule):
    """ list processes """

    dependencies = [ 'pupyps' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="ps", description=self.__doc__)
        self.arg_parser.add_argument('--tree', '-t', action='store_true', help='draw tree')
        self.arg_parser.add_argument('-i', '--info', action='store_true', help='print more info')
        self.arg_parser.add_argument('-x', '--hide', nargs='+', default=[], help='hide processes by pid/name/exe')
        self.arg_parser.add_argument('-a', '--all', action='store_true', help='show kthread')
        self.arg_parser.add_argument('-w', '--wide', action='store_true', help='show all arguments')
        self.arg_parser.add_argument('-s', '--show', nargs='+', type=int, default=[],
                                         help='show process (tree) by pid')

    def run(self, args):
        width, _ = terminal_size()
        root, tree, data = self.client.conn.modules.pupyps.pstree()
        data = { int(k):v for k,v in obtain(data).iteritems() }
        tree = { int(k):v for k,v in obtain(tree).iteritems() }

        colinfo = {'pid': 0}
        for pid in data:
            l = len(str(pid))
            if colinfo['pid'] < l:
                colinfo['pid'] = l
            for column in data[pid]:
                if '_percent' in column:
                    colinfo[column] = 4
                    continue

                l = len(str(data[pid][column]))
                if not column in colinfo:
                    colinfo[column] = l
                else:
                    if colinfo[column] < l:
                        colinfo[column] = l

        try:
            info = ['exe', 'cmdline']
            hide = [
                int(x) if x.isdigit() else x for x in args.hide
            ]
            show = [
                int(x) if x.isdigit() else x for x in args.show
            ]

            if not args.all and self.client.is_linux():
                hide.append(2)

            if args.info:
                info = [ 'username', 'cpu_percent', 'memory_percent' ] + info

            if args.tree:
                show = show or [ root ]

                for item in show:
                    print_pstree(
                        self.stdout, item, tree, data,
                        width=None if args.wide else width, colinfo=colinfo, info=info,
                        hide=hide, first=(item == root)
                    )
            else:
                data = [ x for x in data if x in args.show ] if args.show else data
                print_ps(
                    self.stdout, data, width=None if args.wide else width,
                    colinfo=colinfo, info=info, hide=hide
                )

        except Exception, e:
            logging.exception(e)

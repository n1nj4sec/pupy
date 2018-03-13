# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyOutput import Color, TruncateToTerm, MultiPart, Table
from modules.lib.utils.shell_exec import shell_exec
import logging
import re

__class_name__="PsModule"

ADMINS = ('NT AUTHORITY\SYSTEM', 'root')

def gen_colinfo(data):
    colinfo = {'pid': 0}
    for pid in data:
        l = len(str(pid))
        if colinfo['pid'] < l:
            colinfo['pid'] = l
        for column in data[pid]:
            if '_percent' in column:
                colinfo[column] = 4
                continue
            if type(data[pid][column]) not in (str,unicode,int,float):
                continue

            #fix ascii encode errors
            if type(data[pid][column]) == unicode:
                data[pid][column]=data[pid][column].encode('utf8', 'replace')

            l = len(str(data[pid][column]))
            if not column in colinfo:
                colinfo[column] = l
            else:
                if colinfo[column] < l:
                    colinfo[column] = l

    return colinfo

def to_string(value):
    if type(value) == unicode:
        return value
    elif type(value) != str:
        return str(value)

    try:
        return value.decode('utf-8')
    except:
        return value.decode('latin1')

def gen_columns(record, colinfo):
    columns = {}

    if type(record['cmdline']) is not list:
        record['cmdline'] = [record['cmdline']]

    columns['name'] = record.get('name') or '?'
    columns['cmdline'] = ' '.join([
        x for x in record['cmdline'][1:] if x.strip()
    ]) if record.get('cmdline') else ''
    columns['exe'] = record.get('exe') or '{{{}}}'.format(columns['name'])
    columns['username'] = record.get('username') or ''
    cpu = record.get('cpu_percent')
    columns['cpu_percent'] = '{:3}%'.format(int(cpu)) if cpu is not None else ' '*4
    mem = record.get('memory_percent')
    columns['memory_percent'] = '{:3}%'.format(int(mem)) if mem is not None else ' '*4

    if colinfo:
        if 'username' in colinfo:
            columns['username'] = '{{:{}}}'.format(colinfo['username']).format(columns['username'])
        columns['pid'] = '{{:{}}}'.format(colinfo['pid']).format(record['pid'])
    else:
        columns['pid'] = '{}'.format(parent)

    return columns

def gen_output_line(columns, info, record):
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

    template = u' '.join(u'{{{}}}'.format(x) for x in info)
    columns = {k:to_string(v) for k,v in columns.iteritems()}
    output = template.format(**columns)

    if color:
        output = Color(output, color)

    return TruncateToTerm(output)

def print_psinfo(fout, families, socktypes, data, colinfo, sections=[]):
    keys = ('id', 'key', 'PROPERTY', 'VAR')
    sorter = lambda x,y: -1 if (
        x in keys and y not in keys
    ) else ( 1 if (y in keys and not x in keys) else cmp(x, y))

    parts = []

    for pid, info in data.iteritems():
        if sections is not None:
            infosecs = {
                'general': []
            }
            for prop, value in info.iteritems():
                if type(value) not in (list, dict):
                    infosecs['general'].append({
                        'PROPERTY': prop,
                        'VALUE': '{:3}%'.format(int(value)) if ('_percent' in prop) else value
                    })
                else:
                    if prop == 'environ':
                        maxvar = max(len(x) for x in value.iterkeys())
                        maxval = max(len(x) for x in value.itervalues())
                        infosecs[prop] = [{
                            'VAR':x, 'VALUE':y
                        } for x,y in value.iteritems()]
                        continue
                    elif prop == 'connections':
                        newvalue = []
                        for connection in value:
                            newvalue.append({
                                'status': connection['status'],
                                'raddr': ':'.join([str(x) for x in connection['raddr']]),
                                'laddr': ':'.join([str(x) for x in connection['laddr']]),
                                'family': families[connection['family']],
                                'type': socktypes[connection['type']],
                            })

                        infosecs[prop] = newvalue
                        continue
                    elif prop == 'memory_maps':
                        filtered = ('path', 'rss', 'size')
                    else:
                        filtered = None

                    infosecs[prop] = [{
                        k:v for k,v in item.iteritems() if filtered is None or k in filtered
                    } for item in (value if type(value) == list else [value])]

            if sections:
                for section in sections:
                    section = section.lower()
                    if section in infosecs:
                        labels = sorted(infosecs[section][0], cmp=sorter)
                        parts.append(
                            TruncateToTerm(
                                Table(
                                    infosecs[section],
                                    labels,
                                    section)))

            else:
                for section, table in infosecs.iteritems():
                    labels = sorted(table[0], cmp=sorter)
                    parts.append(TruncateToTerm(Table(table, labels, section)))

            fout(MultiPart(parts))

        else:
            outcols = [ 'pid' ] + [
                x for x in (
                    'cpu_percent', 'memory_percent', 'username', 'exe', 'name', 'cmdline'
                ) if x in colinfo
            ]
            info['pid'] = pid
            columns = gen_columns(info, colinfo)

            fout(gen_output_line(columns, outcols, info)+'\n')


def is_filtered(pid, columns, hide, show):
    default_deny = False

    if not hide and not show:
        return False

    if not hide and show:
        default_deny = True
    if not show and hide:
        default_deny = False

    deny = default_deny

    name = columns['name']
    exe  = columns['exe']
    cmd  = columns['cmdline']

    for hide_rule in hide:
        if type(hide_rule) == int:
            if hide_rule == pid:
                deny = True
        elif hide_rule.match(exe) or hide_rule.match(name) or hide_rule.match(cmd):
                deny = True

    for show_rule in show:
        if type(show_rule) == int:
            if show_rule == pid:
                deny = False
        elif show_rule.match(exe) or show_rule.match(name) or show_rule.match(cmd):
                deny = False

    return deny


def print_pstree(fout, parent, tree, data,
                      prefix='', indent='', colinfo={},
                      info=['exe', 'cmdline'], hide=[],
                      first=False):
    if parent in data:
        data[parent]['pid'] = parent
        columns = gen_columns(data[parent], colinfo)

        if is_filtered(parent, columns, hide, []):
            return

        columns['prefix'] = prefix

        before_tree = [ x for x in info if x in ('cpu_percent', 'memory_percent', 'username') ]
        after_tree = [ x for x in info if x in ('exe', 'name', 'cmdline') ]

        outcols = [ 'pid' ] + before_tree + [ 'prefix' ] + after_tree

        output = gen_output_line(columns, outcols, data[parent])

        fout(output)

    if parent not in tree:
        return

    children = tree[parent][:-1]

    for child in children:
        print_pstree(
            fout, child, tree, data,
            prefix=indent+('┌' if first else '├'), indent=indent + '│ ',
            colinfo=colinfo, info=info, hide=hide
        )
        first = False

    child = tree[parent][-1]
    print_pstree(
        fout, child, tree, data,
        prefix=indent+'└', indent=indent + '  ',
        colinfo=colinfo,
        info=info, hide=hide
    )

def print_ps(fout, data, colinfo={},
                 info=['exe', 'cmdline'], hide=[], show=[]):

    outcols = [ 'pid' ] + [
        x for x in info if x in ('cpu_percent', 'memory_percent', 'username', 'exe', 'name', 'cmdline')
    ]

    for process in sorted(data):
        data[process]['pid'] = process
        columns = gen_columns(data[process], colinfo)

        if is_filtered(process, columns, hide, show):
            continue

        fout(gen_output_line(columns, outcols, data[process]))


@config(cat="admin")
class PsModule(PupyModule):
    """ list processes """

    dependencies = [ 'pupyps' ]
    is_module=False

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="ps", description=self.__doc__)
        self.arg_parser.add_argument('--tree', '-t', action='store_true', help='draw tree')
        self.arg_parser.add_argument('-i', '--info', action='store_true', help='print more info')
        self.arg_parser.add_argument('-I', '--info-sections', nargs='*',
                                         default=None, help='print info for sections (-s only)')
        self.arg_parser.add_argument('-a', '--all', action='store_true', help='show kthread')
        self.arg_parser.add_argument('-w', '--wide', action='store_true', help='show all arguments')
        self.arg_parser.add_argument('-x', '--hide', nargs='+', default=[],
                                     help='hide processes by pid/name/exe (regex)')
        filtering = self.arg_parser.add_mutually_exclusive_group()
        filtering.add_argument('-s', '--show', nargs='+', default=[],
                                         help='show process info (or subtree) by pid/name/exe (regex)')
        filtering.add_argument('-S', '--show-pid', nargs='+', type=int, default=[],
                                         help='show extended process info (or subtree) by pid')

    def run(self, args):
        rpupyps = self.client.remote('pupyps')
        psinfo = self.client.remote('pupyps', 'psinfo')
        pstree = self.client.remote('pupyps', 'pstree')

        families = {
            int(k):v for k,v in self.client.remote_const(
                'pupyps', 'families'
            ).iteritems()
        }

        socktypes = {
            int(k):v for k,v in self.client.remote_const(
                'pupyps', 'socktypes'
            ).iteritems()
        }

        if args.show_pid and not args.tree:
            data = psinfo(args.show_pid)
        else:
            root, tree, data = pstree()
            tree = {
                int(k):v for k,v in tree.iteritems()
            }

        data = {
            int(k):v for k,v in data.iteritems()
        }

        colinfo = gen_colinfo(data)

        try:
            info = ['exe', 'cmdline']
            hide = [
                int(x) if x.isdigit() else re.compile(x, re.IGNORECASE) for x in args.hide
            ]
            show = [
                int(x) if x.isdigit() else re.compile(x, re.IGNORECASE) for x in args.show
            ]

            if not args.all and not args.show and (
                    self.client.is_linux() or self.client.is_android()
            ):
                hide.append(2)

            if args.info:
                info = [ 'username', 'cpu_percent', 'memory_percent' ] + info

            if args.tree:
                show = args.show_pid or [ root ]

                for item in show:
                    print_pstree(
                        self.log, item, tree, data,
                        colinfo=colinfo, info=info,
                        hide=hide, first=(item == root)
                    )
            else:
                if args.show_pid:
                    print_psinfo(
                        self.log, families, socktypes, data, colinfo,
                        sections=args.info_sections or (
                            [ 'general' ] if args.info else args.info_sections
                        )
                    )
                else:
                    data = {
                        x:y for x,y in data.iteritems() if x in args.show_pid
                    } if args.show_pid else data

                    print_ps(
                        self.log, data,
                        colinfo=colinfo, info=info, hide=hide, show=show
                    )

        except Exception, e:
            logging.exception(e)

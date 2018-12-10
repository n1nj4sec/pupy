# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color, TruncateToTerm, MultiPart, Table
from modules.lib import size_human_readable

import logging
import re

__class_name__="PsModule"

ADMINS = (r'NT AUTHORITY\SYSTEM', 'root')

def gen_colinfo(data):
    colinfo = {'pid': 0}
    for pid in data:
        pid_len = len(str(pid))
        if colinfo['pid'] < pid_len:
            colinfo['pid'] = pid_len
        for column in data[pid]:
            if '_percent' in column:
                colinfo[column] = 4
                continue
            if type(data[pid][column]) not in (str,unicode,int,float):
                continue

            #fix ascii encode errors
            if type(data[pid][column]) == unicode:
                data[pid][column]=data[pid][column].encode('utf8', 'replace')
            elif type(data[pid][column]) != str:
                data[pid][column]=str(data[pid][column])

            col_len = len(data[pid][column].decode('utf8', 'replace'))
            if column not in colinfo:
                colinfo[column] = col_len
            else:
                if colinfo[column] < col_len:
                    colinfo[column] = col_len

    return colinfo

def to_string(value):
    tvalue = type(value)

    if tvalue == unicode:
        return value
    elif tvalue != str:
        return unicode(value)

    try:
        return value.decode('utf-8')
    except:
        return value.decode('latin1')

def gen_columns(record, colinfo=None):
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

    if 'pid' not in record:
        return columns

    if colinfo:
        if 'username' in colinfo:
            username = columns['username']
            if type(username) == str:
                username = username.decode('utf-8')
            columns['username'] = u'{{:{}}}'.format(colinfo['username']).format(username)
        columns['pid'] = '{{:{}}}'.format(colinfo['pid']).format(record['pid'])
    else:
        columns['pid'] = '{}'.format(record['pid'])

    return columns

def gen_output_line(columns, info, record, wide=False):
    cpu = record.get('cpu_percent') or 0
    mem = record.get('memory_percent') or 0

    if record.get('self'):
        color = "green"
    elif record.get('status') == 'stopped':
        color = "darkgrey"
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

    if not wide:
        output = TruncateToTerm(output)

    return output

def print_psinfo(fout, families, socktypes, data, colinfo, sections=[], wide=False):
    keys = ('id', 'key', 'PROPERTY', 'VAR', 'TYPE')

    def sorter(x, y):
        return -1 if (
            x in keys and y not in keys
        ) else (1 if (y in keys and x not in keys) else cmp(x, y))

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
                    elif prop == 'memory_info':
                        infosecs[prop] = [{
                            'TYPE':item['KEY'], 'SIZE':size_human_readable(item['VALUE'])
                        } for item in value]
                        continue
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
                                    Color(section.upper(), 'yellow'))))

            else:
                for section, table in infosecs.iteritems():
                    if table:
                        labels = sorted(table[0], cmp=sorter)
                        parts.append(TruncateToTerm(Table(
                            table, labels, Color(section.upper(), 'yellow'))))

            fout(MultiPart(parts))

        else:
            outcols = ['pid'] + [
                x for x in (
                    'cpu_percent', 'memory_percent', 'username',
                    'exe', 'name', 'cmdline', 'status'
                ) if x in colinfo
            ]
            info['pid'] = pid
            columns = gen_columns(info, colinfo)

            fout(gen_output_line(columns, outcols, info, wide))


def is_filtered(pid, columns, hide, show):
    default_deny = False

    if not hide and not show:
        return False

    if not hide and show:
        default_deny = True
    if not show and hide:
        default_deny = False

    deny = default_deny

    name     = columns['name']
    username = columns['username']
    exe      = columns['exe']
    cmd      = columns['cmdline']

    for hide_rule in hide:
        if type(hide_rule) == int:
            if hide_rule == pid:
                deny = True
        elif any(hide_rule.match(x) for x in [exe, name, cmd, username]):
                deny = True

    for show_rule in show:
        if type(show_rule) == int:
            if show_rule == pid:
                deny = False
        elif any(show_rule.match(x) for x in [exe, name, cmd, username]):
                deny = False

    return deny

def check_tree_show(pid, data, show, tree):
    columns = gen_columns(data[pid])
    if data[pid].get('show', None) or not is_filtered(pid, columns, [], show):
        data[pid]['show'] = True
        return True

    for child in tree.get(pid, []):
        columns = gen_columns(data[child])
        if data[child].get('show', None) or not is_filtered(child, columns, [], show):
            data[pid]['show'] = True
            return True

    for child in tree.get(pid, []):
        if not data[pid].get('show', None) is False:
            if check_tree_show(child, data, show, tree):
                data[pid]['show'] = True
                data[child]['show'] = True
                return True
            else:
                data[child]['show'] = False

    data[pid]['show'] = False
    return False

def print_pstree(fout, parent, tree, data,
                      prefix='', indent='', colinfo={},
                      info=['exe', 'cmdline'], hide=[], show=[],
                      first=False, wide=False):
    if parent in data:
        data[parent]['pid'] = parent
        columns = gen_columns(data[parent], colinfo)

        if is_filtered(parent, columns, hide, []):
            return

        if show and not check_tree_show(parent, data, show, tree):
            return

        columns['prefix'] = prefix

        before_tree = [x for x in info if x in ('cpu_percent', 'memory_percent', 'username')]
        after_tree = [x for x in info if x in ('exe', 'name', 'cmdline')]

        outcols = ['pid'] + before_tree + ['prefix'] + after_tree

        output = gen_output_line(columns, outcols, data[parent], wide)

        fout(output)

    if parent not in tree:
        return

    children = tree[parent][:-1]

    for child in children:
        print_pstree(
            fout, child, tree, data,
            prefix=indent+('┌' if first else '├'), indent=indent + '│ ',
            colinfo=colinfo, info=info, hide=hide, show=show, wide=wide
        )
        first = False

    child = tree[parent][-1]
    print_pstree(
        fout, child, tree, data,
        prefix=indent+'└', indent=indent + '  ',
        colinfo=colinfo,
        info=info, hide=hide, show=show, wide=wide
    )

def print_ps(fout, data, colinfo={},
                 info=['exe', 'cmdline'], hide=[], show=[], wide=False):

    outcols = ['pid'] + [
        x for x in info if x in ('cpu_percent', 'memory_percent', 'username', 'exe', 'name', 'cmdline')
    ]

    for process in sorted(data):
        data[process]['pid'] = process
        columns = gen_columns(data[process], colinfo)

        if is_filtered(process, columns, hide, show):
            continue

        fout(gen_output_line(
            columns, outcols, data[process], wide))


@config(cat="admin")
class PsModule(PupyModule):
    """ list processes """

    dependencies = ['pupyps']
    is_module = False

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="ps", description=cls.__doc__)
        cls.arg_parser.add_argument('--tree', '-t', action='store_true', help='draw tree')
        cls.arg_parser.add_argument('-i', '--info', action='store_true', help='print more info')
        cls.arg_parser.add_argument('-I', '--info-sections', nargs='*',
                                         default=None, help='print info for sections (-s only)')
        cls.arg_parser.add_argument('-a', '--all', action='store_true', help='show kthread')
        cls.arg_parser.add_argument('-w', '--wide', action='store_true', help='show all arguments')
        cls.arg_parser.add_argument('-x', '--hide', nargs='+', default=[],
                                     help='hide processes by pid/name/exe (regex)')
        filtering = cls.arg_parser.add_mutually_exclusive_group()
        filtering.add_argument('-s', '--show', nargs='+', default=[],
                                         help='show process info (or subtree) by pid/name/exe (regex)')
        filtering.add_argument('-S', '--show-pid', nargs='+', type=int, default=[],
                                         help='show extended process info (or subtree) by pid')

    def run(self, args):
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
                info = ['username', 'cpu_percent', 'memory_percent'] + info

            if args.tree:
                print_pstree(
                    self.log, root, tree, data,
                    colinfo=colinfo, info=info,
                    hide=hide, show=show,
                    first=True, wide=args.wide
                )
            else:
                if args.show_pid:
                    print_psinfo(
                        self.log, families, socktypes, data, colinfo,
                        sections=args.info_sections or (
                            ['general'] if args.info else args.info_sections
                        ),
                        wide=args.wide
                    )
                else:
                    data = {
                        x:y for x,y in data.iteritems() if x in args.show_pid
                    } if args.show_pid else data

                    print_ps(
                        self.log, data,
                        colinfo=colinfo, info=info, hide=hide, show=show,
                        wide=args.wide
                    )

        except Exception, e:
            logging.exception(e)

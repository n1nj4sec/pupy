# -*- coding: utf-8 -*-

import psutil

import collections
import sys
import os
import time

def pstree():
    data = {}
    tree = {}
    me = psutil.Process()
    try:
        my_user = me.username()
    except:
        my_user = None

    for p in psutil.process_iter():
        if not psutil.pid_exists(p.pid):
            continue

        data[p.pid] = p.as_dict([
            'name', 'username', 'cmdline', 'exe',
            'cpu_percent', 'memory_percent', 'connections'
        ])

        if p.pid == me.pid:
            data[p.pid]['self'] = True
        elif my_user and data[p.pid].get('username') == my_user:
            data[p.pid]['same_user'] = True

        if 'connections' in data[p.pid]:
            data[p.pid]['connections'] = bool(data[p.pid]['connections'])

        try:
            parent = p.parent()
            ppid = parent.pid if parent else 0
            if not ppid in tree:
                tree[ppid] = [p.pid]
            else:
                tree[ppid].append(p.pid)

        except (psutil.ZombieProcess):
            data[p.pid]['name'] = '< Z: ' + data[p.pid]['name'] + ' >'

        except (psutil.NoSuchProcess):
            pass

    # on systems supporting PID 0, PID 0's parent is usually 0
    if 0 in tree and 0 in tree[0]:
        tree[0].remove(0)

    return min(tree), tree, data

def users():
    info = {}
    me = psutil.Process()
    terminals = {}

    if hasattr(me, 'terminal'):
        for p in psutil.process_iter():
            pinfo = p.as_dict(['terminal', 'pid', 'exe', 'name', 'cmdline'])
            if pinfo.get('terminal'):
                terminals[pinfo['terminal'].replace('/dev/', '')] = pinfo

    me = me.username()

    for term in psutil.users():
        terminfo = {
            k:v for k,v in term.__dict__.iteritems() if v and k not in ('host', 'name')
        }

        if 'terminal' in terminfo:
            try:
                terminfo['idle'] = int(time.time()) - int(os.stat(
                    '/dev/{}'.format(terminfo['terminal'])
                ).st_atime)
            except Exception, e:
                pass

            if terminfo['terminal'] in terminals:
                terminfo.update(terminals[terminfo['terminal']])

        host = term.host or '-'

        if not term.name in info:
            info[term.name] = {}

        if not host in info[term.name]:
            info[term.name][host] = []

        if term.name == me or me.endswith('\\'+term.name):
            terminfo['me'] = True

        info[term.name][host].append(terminfo)

    return info

def connections():
    connections = []

    me = psutil.Process()

    for connection in psutil.net_connections():
        obj = { k:v for k,v in connection.__dict__.iteritems() }
        if connection.pid:
            obj.update(
                psutil.Process(connection.pid).as_dict({
                    'pid', 'exe', 'name', 'username'
                })
            )
            if connection.pid == me.pid:
                obj.update({
                    'me': True
                })

        connections.append(obj)

    return connections

def interfaces():
    return {
        'addrs': {
            x:[
                { k:v for k,v in z.__dict__.iteritems() } for z in y
            ] for x,y in psutil.net_if_addrs().iteritems()
        },
        'stats': {
            x:{
                k:v for k,v in y.__dict__.iteritems()
            } for x,y in psutil.net_if_stats().iteritems()
        }
    }

if __name__ == '__main__':
    print users()

# -*- coding: utf-8 -*-

import psutil

import collections
import sys

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

if __name__ == '__main__':
    print pstree()

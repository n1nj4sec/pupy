# -*- coding: utf-8 -*-

import psutil

import collections
import sys
import os
import time
import socket
import struct
import netaddr
import time

families = {
    v:k[3:] for k,v in socket.__dict__.iteritems() if k.startswith('AF_')
}
families.update({-1: 'LINK'})

socktypes = {
    v:k[5:] for k,v in socket.__dict__.iteritems() if k.startswith('SOCK_')
}

def psinfo(pids):
    garbage = ( 'num_ctx_switches', 'memory_full_info', 'cpu_affinity' )
    data = {}

    for pid in pids:
        try:
            process = psutil.Process(pid)
        except:
            continue

        info = {}
        for key, val in process.as_dict().iteritems():
            if key in garbage:
                continue

            newv = None
            if type(val) == list:
                newv = []
                for item in val:
                    if hasattr(item, '__dict__'):
                        newv.append({
                            k:v for k,v in item.__dict__.iteritems()
                        })
                    else:
                        newv.append(item)

                if all([type(x) in (str, unicode) for x in newv]):
                    newv = ' '.join(newv)
            else:
                if hasattr(val, '__dict__'):
                    newv = [{
                        'KEY': k, 'VALUE':v
                    } for k,v in val.__dict__.iteritems()]
                else:
                    newv = val

            info.update({key: newv})

        data.update({
            pid: info
        })

    return data

def pstree():
    data = {}
    tree = {}
    me = psutil.Process()
    try:
        my_user = me.username()
    except:
        try:
            import getpass
            my_user = getpass.getuser()
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

    try:
        me = me.username()
    except:
        try:
            import getpass
            me = getpass.getuser()
        except:
            me = ''

    for term in psutil.users():
        terminfo = {
            k:v for k,v in term.__dict__.iteritems() if v and k not in ('host', 'name')
        }

        if 'pid' in terminfo:
            pinfo = psutil.Process(terminfo['pid']).as_dict(['exe', 'cmdline', 'name'])
            terminfo.update(pinfo)

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
        obj = {
            k:getattr(connection, k) for k in (
                'family', 'type', 'laddr', 'raddr', 'status'
            )
        }
        try:
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
        except:
            pass

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
                k:v for k,v in (
                    y.__dict__.iteritems() if hasattr(y, '__dict__') else
                    zip(('isup', 'duplex', 'speed', 'mtu'), y)
            )
            } for x,y in psutil.net_if_stats().iteritems()
        }
    }

def cstring(string):
    return string[:string.find('\x00')]

def convrecord(item):
    return item if type(item) in (int,long) else cstring(item)

def wtmp(input='/var/log/wtmp'):
    retval = []
    WTmp = struct.Struct('hi32s4s32s256shhiii4I20s')

    login_type = {
        0: None,
        1: 'runlevel',
        2: 'boot',
        3: 'time_new',
        4: 'time_old',
        5: 'init',
        6: 'session',
        7: 'process',
        8: 'terminated',
        9: 'accounting',
    }

    now = time.time()

    with open('/var/log/wtmp') as wtmp:
        while True:
            data = wtmp.read(WTmp.size)
            if not data or len(data) != WTmp.size:
                break

            items = [ convrecord(x) for x in WTmp.unpack(data) ]
            itype = login_type[items[0]]
            if not itype:
                continue

            if itype in ('runlevel', 'terminated'):
                for record in retval:
                    if record['end'] == -1:
                        if itype == 'runlevel' and items[4] == 'shutdown':
                            record['end'] = items[9]
                            record['duration'] = record['end'] - record['start']
                        elif itype == 'terminated':
                            if items[1] == 0:
                                if record['line'] == items[2]:
                                    record['end'] = items[9]
                                    record['duration'] = record['end'] - record['start']
                                    break
                            else:
                                if record['type'] in ('session', 'process') and record['pid'] == items[1]:
                                    record['end'] = items[9]
                                    record['duration'] = record['end'] - record['start']
                                    record['termination'] = items[6]
                                    record['exit'] = items[7]
                                    break

                    if record['type'] == 'runlevel' and record['user'] == 'shutdown':
                        break

            ipbin = items[11:15]
            if all([x==0 for x in ipbin[1:]]):
                ipaddr = str(netaddr.IPAddress(socket.htonl(ipbin[0])))
            else:
                data = struct.pack('IIII', *ipbin).encode('hex')
                ipaddr = ''
                while data is not '':
                    ipaddr = ipaddr + ':'
                    ipaddr = ipaddr + data[:4]
                    data = data[4:]
                ipaddr = str(netaddr.IPAddress(ipaddr[1:]))

            retval.insert(0, {
                'type': itype,
                'pid': items[1],
                'line': items[2],
                'id': items[3],
                'user': items[4],
                'host': items[5],
                'termination': items[6],
                'exit': items[7],
                'session': items[8],
                'start': items[9],
                'ip': ipaddr,
                'end': -1,
                'duration': now - items[9]
            })

    return {
        'now': now,
        'records': retval
    }

def lastlog(log='/var/log/lastlog'):
    import pwd

    result = {}
    LastLog = struct.Struct('I32s256s')

    with open(log) as lastlog:
        uid = 0
        while True:
            data = lastlog.read(LastLog.size)
            if not data or len(data) != LastLog.size:
                break

            time, line, host = LastLog.unpack(data)
            line = cstring(line)
            host = cstring(host)
            if time:
                try:
                    name = pwd.getpwuid(uid).pw_name
                except:
                    name = uid

                result[name] = {
                    'time': time,
                    'line': line,
                    'host': host,
                }
            uid += 1

    return result

if __name__ == '__main__':
    import datetime
    for result in wtmp():
        if result['type'] in ('process', 'boot'):
            print '{:12s} {:5d} {:7} {:8s} {:8s} {:16s} {:3} {:3} {} - {}'.format(
                result['type'],
                result['pid'],
                result['id'],
                result['user'], result['line'], result['host'],
                result['termination'], result['exit'],
                datetime.datetime.fromtimestamp(result['start']),
                datetime.datetime.fromtimestamp(result['end']) if result['end'] != -1 else 'logged in',
            )

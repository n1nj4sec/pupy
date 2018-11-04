# -*- coding: utf-8 -*-

import psutil

import sys
import os
import socket
import struct
import netaddr
import time

families = {
    v:k[3:] for k,v in socket.__dict__.iteritems() if k.startswith('AF_')
}

try:
    families.update({psutil.AF_LINK: 'LINK'})
except:
    pass

families.update({-1: 'LINK'})

socktypes = {
    v:k[5:] for k,v in socket.__dict__.iteritems() if k.startswith('SOCK_')
}

def to_unicode(x):
    tx = type(x)
    if tx == unicode:
        return x
    elif tx == str:
        return x.decode(sys.getfilesystemencoding())
    else:
        return x

def psinfo(pids):
    data = {}
    garbage = (
        'num_ctx_switches', 'memory_full_info', 'cpu_affinity'
    )

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
                            k:to_unicode(v) for k,v in item.__dict__.iteritems()
                        })
                    else:
                        newv.append(to_unicode(item))

                if all([type(x) in (str, unicode) for x in newv]):
                    newv = to_unicode(' '.join(newv))
            elif hasattr(val, '__dict__'):
                newv = [{
                    'KEY': k, 'VALUE':to_unicode(v)
                } for k,v in val.__dict__.iteritems()]
            else:
                newv = to_unicode(val)

            info.update({key: newv})

        data[pid] = info

    return data

def safe_as_dict(p, data):
    try:
        return p.as_dict(data)
    except:
        data = list(data)
        if 'cmdline' in data:
            data.remove('cmdline')

        result = p.as_dict(data)
        result['cmdline'] = None
        return result

def pstree():
    data = {}
    tree = {}
    me = psutil.Process()
    try:
        my_user = to_unicode(me.username())
    except:
        try:
            import getpass
            my_user = getpass.getuser()
        except:
            my_user = None

    for p in psutil.process_iter():
        if not psutil.pid_exists(p.pid):
            continue

        data[p.pid] = {
            k:to_unicode(v) for k,v in safe_as_dict(p, [
                'name', 'username', 'cmdline', 'exe', 'status',
                'cpu_percent', 'memory_percent', 'connections',
            ]).iteritems()
        }

        if p.pid == me.pid:
            data[p.pid]['self'] = True
        elif my_user and data[p.pid].get('username') == my_user:
            data[p.pid]['same_user'] = True

        if 'connections' in data[p.pid]:
            data[p.pid]['connections'] = bool(data[p.pid]['connections'])

        parent = None

        try:
            parent = p.parent()

        except (psutil.ZombieProcess):
            data[p.pid]['name'] = '< Z: ' + data[p.pid]['name'] + ' >'

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            data[p.pid]['name'] = '< ?: ' + data[p.pid]['name'] + ' >'

        ppid = parent.pid if parent else 0
        if ppid not in tree:
            tree[ppid] = [p.pid]
        else:
            tree[ppid].append(p.pid)

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
            pinfo = safe_as_dict(p, ['terminal', 'pid', 'exe', 'name', 'cmdline'])
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
            k:to_unicode(v) for k,v in term.__dict__.iteritems() if v and k not in ('host', 'name')
        }

        if 'pid' in terminfo:
            try:
                pinfo = {
                    k:to_unicode(v) for k,v in safe_as_dict(psutil.Process(
                        terminfo['pid']), [
                            'exe', 'cmdline', 'name'
                        ]).iteritems()
                }

                terminfo.update(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                terminfo.update({
                    'pid': terminfo['pid'],
                    'dead': True,
                })

        if 'terminal' in terminfo:
            try:
                terminfo['idle'] = int(time.time()) - int(os.stat(
                    '/dev/{}'.format(terminfo['terminal'])
                ).st_atime)
            except:
                pass

            if terminfo['terminal'] in terminals:
                terminfo.update(terminals[terminfo['terminal']])

        host = term.host or '-'

        if term.name not in info:
            info[term.name] = {}

        if host not in info[term.name]:
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
                obj.update({
                    k:to_unicode(v) for k,v in psutil.Process(
                        connection.pid).as_dict({
                           'pid', 'exe', 'name', 'username'
                       }).iteritems()
                })
                if connection.pid == me.pid:
                    obj.update({
                        'me': True
                    })
        except:
            pass

        connections.append(obj)

    return connections

def _tryint(x):
    try:
        return int(x)
    except:
        return str(x)

def interfaces():
    try:
        addrs = {
            to_unicode(x):[
                {
                    k:_tryint(getattr(z,k)) for k in dir(z) if not k.startswith('_')
                } for z in y
            ] for x,y in psutil.net_if_addrs().iteritems()
        }
    except:
        addrs = None

    try:
        stats = {
            to_unicode(x):{
                k:_tryint(getattr(y,k)) for k in dir(y) if not k.startswith('_')
            } for x,y in psutil.net_if_stats().iteritems()
        }
    except:
        stats = None

    return {
        'addrs': addrs,
        'stats': stats
    }

def drives():
    partitions = []
    for partition in psutil.disk_partitions():
        record = {
            'device': partition.device,
            'mountpoint': partition.mountpoint,
            'fstype': partition.fstype,
            'opts': partition.opts
        }

        try:
            usage = psutil.disk_usage(partition.mountpoint)
            record.update({
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent
            })
        except:
            pass

        partitions.append(record)

    return partitions

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

            items = [
                convrecord(x) for x in WTmp.unpack(data)
            ]

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

def get_win_services():
    return [
        {
            k:to_unicode(v) for k,v in service.as_dict().iteritems()
        } for service in psutil.win_service_iter()
    ]


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

# -*- coding: utf-8 -*-

import pwd
import os
import sys
import subprocess

if not hasattr(sys, '_BECOME_INITIALIZED'):
    sys._SAVED_UID = os.getuid()
    sys._SAVED_GID = os.getgid()
    sys._SAVED_GROUPS = os.getgroups()
    sys._SAVED_CWD = os.getcwdu()
    sys._SAVED_ENV = os.environ.copy()
    sys._BECOME_INITIALIZED = True

def become(user):
    try:
        userinfo = pwd.getpwuid(int(user))
    except:
        try:
            userinfo = pwd.getpwnam(user)
        except:
            raise ValueError('User {} not found'.format(user))

    if os.geteuid() == userinfo.pw_uid:
        return

    sys._SAVED_UID = os.geteuid()
    sys._SAVED_GID = os.getegid()
    sys._SAVED_GROUPS = os.getgroups()
    sys._SAVED_CWD = os.getcwdu()
    sys._SAVED_ENV = os.environ.copy()

    os.initgroups(userinfo.pw_name, userinfo.pw_gid)
    os.setegid(userinfo.pw_gid)
    os.seteuid(userinfo.pw_uid)

    os.environ['HOME'] = userinfo.pw_dir
    os.environ['USER'] = userinfo.pw_name
    os.environ['LOGNAME'] = userinfo.pw_name
    os.environ['SHELL'] = userinfo.pw_shell
    os.environ['XAUTHORITY'] = os.path.join(
        userinfo.pw_dir, '.Xauthority'
    )

    user_dbus_socket = os.path.join(
        '/', 'var', 'run', 'user', str(userinfo.pw_uid), 'dbus', 'user_bus_socket'
    )

    if os.path.exists(user_dbus_socket):
        os.environ['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path='+user_dbus_socket
    elif 'DBUS_SESSION_BUS_ADDRESS' in os.environ:
        del os.environ['DBUS_SESSION_BUS_ADDRESS']

    for var in os.environ.keys():
        if var.startswith(('XDG_', 'GDM', 'DESKTOP_')):
            del os.environ[var]

    if 'PATH' in os.environ:
        os.environ['PATH'] += ':'.join([
            os.path.join(userinfo.pw_dir, '.local', 'bin'),
            os.path.join(userinfo.pw_dir, 'bin')
        ])

    try:
        os.chdir(userinfo.pw_dir)
    except:
        pass

    try:
        for line in subprocess.check_output([
            userinfo.pw_shell, '-c', '; '.join([
                '[ -f /etc/profile ] && source /etc/profile >/dev/null 2>/dev/null',
                '[ -f ~/.profile ] && source ~/.profile >/dev/null 2>/dev/null',
                'printenv'
            ])
        ]).split('\n'):
            if line and '=' in line:
                k, v = line.split('=', 1)
                os.environ[k] = v
    except:
        pass

def restore():
    if os.getegid() == sys._SAVED_UID:
        return

    os.seteuid(sys._SAVED_UID)
    os.setegid(sys._SAVED_GID)
    os.setgroups(sys._SAVED_GROUPS)
    os.chdir(sys._SAVED_CWD)
    os.environ = sys._SAVED_ENV

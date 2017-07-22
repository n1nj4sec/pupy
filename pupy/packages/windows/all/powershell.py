# -*- coding: utf-8 -*-

import pupy
import base64
import subprocess
import os
import zlib
import threading
import re
import random
import Queue
import string
import codecs

class PowerHostUninitialized(Exception):
    pass

class PowerShellUninitialized(Exception):
    pass

class PowerShellInitializationFailed(Exception):
    pass

class PowerShellV2NotInstalled(Exception):
    pass

class Request(object):
    def __init__(self, rid, storage, expression, timeout=None, continious=False):
        self._expression = expression
        self._event = threading.Event()
        self._storage = storage
        self._timeout = timeout
        self._result = '' if continious else None
        self._continious = continious
        self._archive = []
        self._rid = rid
        self._completed = False

    @property
    def expression(self):
        return self._expression

    @property
    def ready(self):
        return self._event.is_set()

    @property
    def result(self):
        self._event.wait(timeout=self._timeout)
        result = self._result

        if self._rid in self._storage:
            if self._archive:
                result = ''.join([
                    zlib.decompress(x) for x in self._archive
                ]) + result
                self._archive = []

            del self._storage[self._rid]

        if self._continious:
            self._event.clear()

        return result

    @result.setter
    def result(self, value):
        if value:
            if self._continious:
                if not self._rid in self._storage:
                    self._storage[self._rid] = value
                else:
                    self._storage[self._rid] += value

                if len(self._storage[self._rid]) > 1024*1024:
                    self._archive.append(zlib.compress(self._storage[self._rid], 9))
                    self._storage[self._rid] = ''
            else:
                self._storage[self._rid] = value

            # Preserve ref
            self._result = self._storage[self._rid]

        else:
            self._completed = False

        if not self._completed:
            self._event.set()


class PowerShell(threading.Thread):
    def __init__(self, host, name, content, try_x64=False, daemon=False, width=None, v2=True):
        super(PowerShell, self).__init__()
        self.daemon = True

        self._content = zlib.compress(content) if content else None
        self._try_x64 = try_x64
        self._completed = threading.Event()
        self._initialized = False
        self._pipe = None
        self._executable = u'powershell.exe'
        self._queue = None
        self._name = name
        self._host = host
        self._daemon = daemon
        self._daemon_request = None
        self._width = width or 4096
        self._rid = 0
        self._v2 = v2

        if try_x64:
            native = ur'C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe'
            if os.path.exists(native):
                self._executable = native

        self._args = [
            self._executable, u'-W', u'hidden', u'-I', u'Text', u'-C', u'-'
        ]

        self._initialize()

    @property
    def v2(self):
        return self._v2

    def _initialize(self):
        if self._pipe:
            return

        if self._v2:
            args = [
                self._args[0], u'-v', u'2',
            ] + self._args[1:]
        else:
            args = self._args

        self._pipe = subprocess.Popen(
            args, bufsize=0, universal_newlines=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE,
        )

        preamble_complete = self._random()

        request =  '\n'.join([
            '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
            '$OutputEncoding = [Console]::OutputEncoding',
            'Write-Host {}'.format(preamble_complete)
        ]) + '\n'

        self._pipe.stdin.write(request)
        self._pipe.stdin.flush()

        print "WAITING FOR ", preamble_complete
        data = self._pipe.stdout.readline()

        if 'Version v2.0.50727 of the .NET Framework is not installed'.encode('UTF-16LE') in data:
            self.stop()
            raise PowerShellV2NotInstalled()

        elif not data or not preamble_complete in data:
            print "First line: ", repr(data)
            print '.NET Framework is not installed' in data
            self.stop()
            raise PowerShellInitializationFailed()

        if not self._content:
            return

        content = zlib.decompress(self._content)
        content = re.sub('Write-Host ', 'Write-Output ', content, flags=re.I)

        self._invoke_expression(content)


    def _invoke_expression(self, content, dest=None, pipe=None):
        if not self._pipe:
            raise PowerShellUninitialized()

        if not content:
            return

        var = self._random()
        tmp = self._random()

        self._pipe.stdin.write('${}=""\n'.format(var))
        part = 20000
        encoded = base64.b64encode(content)

        for portion in [encoded[i:i+part] for i in range(0, len(encoded), part)]:
            self._pipe.stdin.write('${}+="{}"\n'.format(var, portion))

        request ='${tmp}=[System.Text.Encoding]::UTF8.GetString(' \
          '[System.Convert]::FromBase64String(${var}));' \
          '{dest}Invoke-Expression ${tmp}{pipe};' \
          ' Remove-Variable {var}; Remove-Variable {tmp}\n'

        if dest:
            pipe = '{}Format-Table -Property * -AutoSize | Out-String -Width {}'.format(
                '{} |'.format(pipe) if pipe else '',
                self._width
            )

        request = request.format(
            tmp=tmp, var=var,
            dest='${}='.format(dest) if dest else '',
            pipe='| {}'.format(pipe) if pipe else ''
        )

        self._pipe.stdin.write(request)
        self._pipe.stdin.flush()


    def run(self):
        request = self._queue.get()

        if self._daemon:
            self._execute(request.expression)
            while self._pipe:
                try:
                    data = self._pipe.stdout.readline()
                    request.result = data

                    if not data:
                        break

                except:
                    request.result = None
                    self.stop()
                    break

        else:
            while request:
                request.result = self._execute(request.expression)
                request = self._queue.get()


    def _random(self):
        return ''.join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(32)
        )

    def _execute(self, expression):
        if self._daemon:
            if not expression.endswith('\n'):
                expression = expression + '\n'

            self._invoke_expression(expression)
            return

        SOL = self._random()
        EOL = ' ' + self._random()
        res = self._random()

        self._invoke_expression(expression, res)
        self._pipe.stdin.write(
            'Write-Host "{SOL}${res}{EOL}"; Remove-Variable {res}\n'.format(
                SOL=SOL, res=res, EOL=EOL
            )
        )
        self._pipe.stdin.flush()

        response = ''

        while not response.endswith(EOL+'\n'):
            data = self._pipe.stdout.readline()
            if not data:
                break

            response += data.replace('\r\n', '\n')

        sol_at = response.find(SOL)
        return response[
            sol_at+len(SOL):-(len(EOL)+1)
        ].strip(), response[:sol_at]

    def execute(self, expression, async=False, timeout=None):
        if self._daemon:
            async = True

            if self._daemon_request:
                self._execute(expression)
                return self._daemon_request

        if self._queue:
            request = Request(
                self._rid,
                self._host.results[self._name],
                expression,
                timeout,
                self._daemon
            )

            if self._daemon:
                self._daemon_request = request

            self._rid += 1
            self._queue.put(request)
            if async:
                return request
            else:
                return request.result

        elif not self._queue and async:
            self._queue = Queue.Queue()
            self._host.results[self._name] = {}
            self.start()
            return self.execute(expression, async, timeout)

        else:
            return self._execute(expression)

    def stop(self):
        if self._queue:
            self._queue.put(None)

        if not self._pipe:
            return True

        try:
            self._pipe.stdin.write('exit\n')
            self._pipe.stdin.flush()
        except:
            pass

        try:
            self._pipe.terminate()
            result = self._pipe.poll() is not None
        except:
            result = None

        try:
            self._pipe.stdout.read()
        except:
            pass

        self._pipe = None
        return result

    def __del__(self):
        try:
            self.stop()
        except:
            pass

class PowerHost(object):
    def __init__(self, manager):
        self._powershells = {}
        self._manager = manager
        self._v2 = True
        self.results = {}

    def register(self, name, content, force=False, try_x64=False, daemon=False, width=None, v2=None):
        v2 = self._v2 if v2 is None else v2
        if name in self._powershells:
            if not force:
                raise ValueError('{} already registered'.format(name))

            self._powershells[name].stop()

        try:
            self._powershells[name] = PowerShell(
                self, name, content, try_x64, daemon, width, v2
            )

        except PowerShellV2NotInstalled:
            self._v2 = False
            self._powershells[name] = PowerShell(
                self, name, content, try_x64, daemon, width, False
            )

    def registered(self, name):
        return name in self._powershells

    def unregister(self, name):
        if not name in self._powershells:
            raise ValueError('{} is not registered'.format(name))

        self._powershells[name].stop
        del self._powershells[name]

    def function(self, name, expression):
        if not name in self._powershells:
            raise ValueError('{} is not registered'.format(name))

        return lambda: self._powershells[name].execute(
            expression
        )

    def call(self, name, expression, async=False, timeout=None):
        if not name in self._powershells:
            raise ValueError('{} is not registered'.format(name))

        return self._powershells[name].execute(expression, async, timeout)

    def stop(self):
        for name in self._powershells.keys():
            self._powershells[name].stop()
            del self._powershells[name]

    # Compatibility

    def start(self):
        pass

    def event(self, event):
        pass

    @property
    def name(self):
        return type(self).__name__

    @property
    def dirty(self):
        return False

    @property
    def stopped(self):
        return not self._powershells

def loaded(name):
    powershell = pupy.manager.get(PowerHost)
    if not powershell:
        return False

    return powershell.registered(name)

def load(name, content, force=False, try_x64=False, daemon=False, width=None, v2=None):
    powershell = pupy.manager.get(PowerHost) or \
      pupy.manager.create(PowerHost)

    if not powershell:
        raise PowerHostUninitialized()

    powershell.register(name, content, force, try_x64, daemon, width, v2)

def unload(name):
    powershell = pupy.manager.get(PowerHost)
    if not powershell:
        raise PowerHostUninitialized()

    powershell.unregister(name)

def call(name, expression, async=False, timeout=None, content=None, try_x64=False):
    powershell = pupy.manager.get(PowerHost) or \
      pupy.manager.create(PowerHost)

    if not powershell:
        raise PowerHostUninitialized()

    if content and not loaded(name):
        load(name, content, force=True, try_x64=try_x64)

    try:
        return powershell.call(name, expression, async, timeout)

    finally:
        if content:
            unload(name)

@property
def results():
    powershell = pupy.manager.get(PowerHost)
    if not powershell:
        raise PowerHostUninitialized()

    return powershell.results

def stop():
    pupy.manager.stop(PowerHost)

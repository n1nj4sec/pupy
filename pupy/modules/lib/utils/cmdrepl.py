# -*- coding: utf-8 -*-

from threading import Thread
from cmd import Cmd

class CmdRepl(Cmd):
    def __init__(self, stdout, write_cb, completion, CRLF=False, interpreter=None, codepage=None):
        self._write_cb = write_cb
        self._complete = completion
        self._codepage = codepage
        self.prompt = '\r'
        self._crlf = ('\r\n' if CRLF else '\n')
        self._interpreter = interpreter
        self._setting_prompt = False
        self._last_cmd = None
        Cmd.__init__(self, stdout=stdout)

    @staticmethod
    def thread(*args, **kwargs):
        repl = CmdRepl(*args, **kwargs)
        repl.set_prompt()

        repl_thread = Thread(target=repl.cmdloop)
        repl_thread.daemon = True
        repl_thread.start()

        return repl, repl_thread

    def _con_write(self, data):
        if self._setting_prompt:
            if self.prompt in data:
                self._setting_prompt = False
            return

        if not self._complete.is_set():
            if self._codepage:
                data = data.decode(self._codepage, errors='replace')

            self.stdout.write(data)
            self.stdout.flush()
            if '\n' in data:
                self.prompt = data.rsplit('\n', 1)[-1]
            else:
                self.prompt += data

    def do_EOF(self, line):
        return True

    def do_help(self, line):
        self.default(' '.join(['help', line]))

    def completenames(self):
        return []

    def precmd(self, line):
        if self._complete.is_set():
            return 'EOF'
        else:
            return line

    def postcmd(self, stop, line):
        if stop or self._complete.is_set():
            return True

    def emptyline(self):
        pass

    def default(self, line):
        if self._codepage:
            line = line.decode('utf-8').encode(self._codepage)

        self._write_cb(line + self._crlf)
        self.prompt = ''

    def postloop(self):
        self._complete.set()

    def set_prompt(self, prompt='# '):
        methods = {
            'cmd.exe': ['set PROMPT={}'.format(prompt)],
            'sh': ['export PS1="{}"'.format(prompt)]
        }

        method = methods.get(self._interpreter, None)
        if method:
            self._setting_prompt = True
            self.prompt = prompt
            self._write_cb(self._crlf.join(method) + self._crlf)

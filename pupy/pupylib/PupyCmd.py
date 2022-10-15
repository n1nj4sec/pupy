# -*- coding: utf-8 -*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived
# from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------
import sys
import cmd
import os
import os.path
import traceback
import time

import termios
import tty
import pty
import select
import fcntl
import array
import readline
import logging

from threading import Thread, Event, Lock
from subprocess import Popen, PIPE, STDOUT

from network.lib.base_launcher import LauncherError

from .PupyErrors import PupyModuleExit, PupyModuleError, PupyModuleUsageError
from .PupyModule import (
    REQUIRE_NOTHING, REQUIRE_REPL, REQUIRE_TERMINAL
)
from .PupyCompleter import CompletionContext
from .PupyVersion import BANNER, UPSTREAM, DISCLAIMER
from .PupyOutput import (
    Text, Line, Color, Title, NewLine, Info,
    ServiceInfo, Warn, Error, Success,  Indent
)

from .utils.term import (
    colorize, as_term_bytes, consize, fix_stdout,
    SHADOW_SCREEN_TO, SHADOW_SCREEN_FROM,
    CUR_LEFT, STOR_CUR, LOAD_CUR, DEL_RIGHT,
    DEFAULT_MULTIBYTE_CP
)

from .PupySignalHandler import set_signal_winch

from commands import Commands, InvalidCommand

from termios import TCSANOW

from . import getLogger
logger = getLogger('cmd')

if sys.version_info.major > 2:
    xrange = range

    def bm_byte(x):
        return bytes((x,))

else:
    def bm_byte(x):
        return x


class ObjectStreamPipeConsumer(Thread):
    __slots__ = (
        'pipe', '_write', '_nocrlf',
        '_write_lock', '_read_lock'
    )

    def __init__(self, pipe, write, nocrlf):
        self.pipe = Popen(
            pipe, shell=True,
            stdin=PIPE, stdout=PIPE, stderr=STDOUT
        )
        self._write = write
        self._nocrlf = nocrlf
        self._write_lock = Lock()
        self._read_lock = Lock()

        super(ObjectStreamPipeConsumer, self).__init__()
        self.daemon = True

    def write(self, message):
        text = as_term_bytes(message)
        text = text.strip(' ')

        if not text:
            return

        if not self._nocrlf:
            text += '\n'

        with self._write_lock:
            if not isinstance(text, bytes):
                text = text.encode('utf-8')

            self.pipe.stdin.write(text)

    def close(self):
        with self._write_lock:
            self.pipe.stdin.close()

        with self._read_lock:
            self.pipe.wait()

    def run(self):
        while True:
            with self._read_lock:
                chunk = self.pipe.stdout.read()

            if not chunk:
                break

            self._write(chunk)


class ObjectStream(object):
    __slots__ = ('_buffer', '_display', '_stream', '_pipe', '_pipe_cmd')

    def __init__(self, display=None, stream=False, pipe=None):
        self._buffer = []
        self._display = display
        self._stream = stream
        self._pipe_cmd = pipe
        self._pipe = None

    def write(self, data):
        if self._pipe_cmd:
            if self._pipe is None:
                self._pipe = ObjectStreamPipeConsumer(
                    self._pipe_cmd,
                    self._display if self._display else self._buffer.append,
                    self._stream
                )
                self._pipe.start()

            self._pipe.write(data)

        elif self._display:
            self._display(data, nocrlf=self._stream)
        else:
            self._buffer.append(data)

    def close(self):
        if self._pipe:
            self._pipe.close()
            self._pipe.join()
            self._pipe = None

    def flush(self):
        pass

    def getvalue(self):
        self.close()

        blocks = self._buffer
        self._buffer = []
        return blocks

    @property
    def is_stream(self):
        return self._stream

    def __nonzero__(self):
        return bool(self._buffer)


class IOGroup(object):
    __slots__ = ('_stdin', '_stdout', '_logger', '_pipe')

    def __init__(self, stdin, stdout, logger=None, pipe=None):
        self._stdin = stdin
        self._stdout = stdout
        self._logger = logger
        self._pipe = None

        if pipe:
            self._pipe = Popen(
                pipe, shell=True,
                stdout=stdout, stdin=PIPE, stderr=STDOUT
            )

            self._stdout = self._pipe.stdin

    @property
    def stdin(self):
        return self._stdin

    @property
    def stdout(self):
        return self._stdout

    def set_logger(self, logger):
        if self._logger:
            self._logger.close()

        self._logger = logger

    def set_title(self, title):
        pass

    def as_bytes(self, msg):
        return as_term_bytes(msg)

    def close(self):
        if self._pipe:
            self._pipe.communicate()

        if isinstance(self._stdout, ObjectStream):
            self._stdout.close()

    @property
    def consize(self):
        return 80, 25


class RawTerminal(IOGroup):
    __slots__ = (
        '_active',
        '_specials',
        '_special_state',
        '_special_activated',
        '_shadow_screen',
        '_last_window_size',
        '_on_winch',
        '_closed',
        '_tc_settings',
        '_winch_handler',
        '_stdin_fd',
        '_stdout_fd'
    )

    def __init__(self, stdin, stdout, shadow_screen=True):
        self._stdin = stdin
        self._stdout = stdout
        self._specials = {}
        self._on_winch = None
        self._active = False
        self._tc_settings = None
        self._winch_handler = None
        self._shadow_screen = shadow_screen

        self._stdin_fd = None
        self._special_state = b''
        self._special_activated = False

        self._last_window_size = None

    def _get_window_size(self):
        buf = array.array('H', [0, 0, 0, 0])
        fcntl.ioctl(pty.STDOUT_FILENO, termios.TIOCGWINSZ, buf, True)
        return buf[0], buf[1], buf[2], buf[3]

    @property
    def window_size(self):
        if self._last_window_size is None:
            self._last_window_size = self._get_window_size()

        return self._last_window_size

    def _on_sigwinch(self, signum, frame):
        self._last_window_size = self._get_window_size()

        if self._on_winch is not None:
            self._on_winch(*self._last_window_size)

    def _stdin_read(self):
        buf = b''
        while self._active:
            r, _, _ = select.select([self._stdin], [], [], 0.5)
            if not r:
                continue

            buf_ = array.array('i', [0])

            if fcntl.ioctl(self._stdin, termios.FIONREAD, buf_, 1) == -1:
                break

            if not buf_[0]:
                continue

            buf += os.read(self._stdin_fd, buf_[0])
            if buf:
                break

        return buf

    def __iter__(self):
        self._on_sigwinch(None, None)

        while self._active:
            buf = self._stdin_read()
            if not self._specials:
                if self._active and buf:
                    yield buf
            else:
                self._special_state += buf

                data_buf = b''

                while self._special_state:
                    again = False

                    data_buf = b''
                    special_buf = b''

                    for b in self._special_state:
                        b = bm_byte(b)

                        if self._special_activated:
                            if not special_buf and b != b'~':
                                data_buf += b
                                if b == b'\r':

                                    yield data_buf
                                    self._special_state = self._special_state[
                                        len(data_buf):]

                                    data_buf = b''
                                    again = True
                                    break
                                else:
                                    self._special_activated = False
                                    continue
                            else:

                                special_buf += b
                                if special_buf in self._specials:
                                    cb = self._specials[special_buf]
                                    cb(self)
                                    again = True

                                    self._special_state = self._special_state[
                                        len(special_buf):]
                                    special_buf = b''
                                    self._special_activated = False
                                    break
                                elif not any([
                                            x.startswith(special_buf)
                                            for x in self._specials
                                        ]):
                                    data_buf += special_buf
                                    special_buf = b''
                                    self._special_activated = False
                        else:
                            data_buf += b
                            if b == b'\r':
                                self._special_activated = True

                                yield data_buf
                                self._special_state = self._special_state[
                                    len(data_buf):]

                                data_buf = b''
                                again = True
                                break

                    if not again:
                        break

            if data_buf:

                self._special_state = self._special_state[len(data_buf):]

                yield data_buf

    def __enter__(self):
        self._stdin_fd = self._stdin.fileno()
        self._stdout_fd = self._stdout.fileno()

        self._tc_settings = termios.tcgetattr(self._stdin_fd)
        tty.setraw(self._stdin_fd, TCSANOW)

        if self._on_winch:
            self._winch_handler = set_signal_winch(self._on_sigwinch)

        if self._shadow_screen:
            self._stdout.write(SHADOW_SCREEN_TO)

        self._active = True

    def __exit__(self, type, value, tb):
        self._active = False

        termios.tcsetattr(self._stdin_fd, termios.TCSADRAIN, self._tc_settings)

        if self._on_winch:
            set_signal_winch(self._winch_handler)

        if self._shadow_screen:
            self._stdout.write(SHADOW_SCREEN_FROM)

    def set_on_winch(self, on_winch):
        self._on_winch = on_winch

    def set_mapping(self, sequence, on_sequence):
        if not isinstance(sequence, bytes):
            sequence = sequence.encode()

        if not sequence or len(sequence) < 2 or not sequence.startswith(b'~'):
            raise ValueError(
                'Sequence should start from ~ and be at least 2 symbols'
            )

        self._specials[sequence] = on_sequence

    def write(self, data):
        if self._active:
            os.write(self._stdout_fd, data)

    def close(self):
        self._active = False

    @property
    def consize(self):
        return consize(self._stdout)

    @property
    def closed(self):
        return not self._active


class PupyCmd(cmd.Cmd):
    def __init__(self, pupsrv):
        cmd.Cmd.__init__(self)

        self.stdout = fix_stdout(self.stdout)


        self.pupsrv = pupsrv
        self.dnscnc = pupsrv.dnscnc
        self.config = pupsrv.config

        self.input = sys.stdin
        self.output = sys.stdout

        self.commands = Commands()

        self.display_lock = Lock()

        self.init_readline()

        self._intro = [
            Color(BANNER, 'green'),
            Indent(Color(UPSTREAM, 'cyan')),
            Indent(Color(DISCLAIMER, 'lightred'))
        ]

        self.prompt = colorize('>> ', 'blue', prompt=True)

        self.default_filter = None
        try:
            if not self.config.getboolean('cmdline', 'display_banner'):
                self._intro = []
        except Exception:
            pass
        self.intro=self._make_intro().decode('utf8')

        self.aliases = {}

        for m, _ in self.pupsrv.get_aliased_modules():
            self.aliases[m] = m

        try:
            for command, alias in self.config.items('aliases'):
                logger.debug("Alias: %s => %s", command, alias)
                self.aliases[command] = alias

        except Exception as e:
            logger.exception(
                'Error while parsing aliases from pupy.conf: %s', e
            )

        self.pupsrv.register_handler(self)

    def _make_intro(self):
        return b'\n'.join(
            as_term_bytes(x) for x in self._intro
        )

    def add_motd(self, motd={}):
        for ok in motd.get('ok', []):
            self._intro.append(ServiceInfo(ok + '\n'))

        for fail in motd.get('fail', []):
            self._intro.append(
                Error(fail + '\n') if not issubclass(
                    type(fail), Text
                ) else fail
            )

    def default(self, line):
        return self.execute(line)

    def inject(self, line, clients_filter, message=None):
        self.display_srvinfo(message or 'Inject: {}'.format(line))
        self.execute(line, clients_filter)
        self.display_srvinfo('Action complete')

    def onecmd(self, line):
        """
         class overwritten from stdlib to avoid some disturbing stack traces
        """
        cmd, arg, line = self.parseline(line)
        if not line:
            return self.emptyline()
        if cmd is None:
            return self.default(line)
        self.lastcmd = line
        if line == 'EOF' :
            self.lastcmd = ''
        if cmd == '':
            return self.default(line)
        else:
            try:
                func = getattr(self, 'do_' + cmd)
            except AttributeError:
                func = None
            if not func:
                return self.default(line)
            return func(arg)

    def execute(self, line, clients_filter=None):
        if isinstance(line, bytes):
            line = line.decode(DEFAULT_MULTIBYTE_CP)

        if line.startswith('!'):
            os.system(line[1:])
            return

        try:
            self.commands.execute(
                self.pupsrv, self,
                self.pupsrv.config, line,
                clients_filter)

            self.completion_matches = None

        except PupyModuleUsageError as e:
            prog, message, usage = e.args
            self.display(Line(Error(message, prog)))
            self.display(usage)

        except PupyModuleExit:
            pass

        except InvalidCommand as e:
            self.display(Error(
                'Unknown (or unavailable) command {}. Use help -M to '
                'list available commands and modules'.format(e)))

        except (PupyModuleError, LauncherError,
                NotImplementedError, ValueError) as e:
            if str(e) and str(e) != 'None':
                self.display(Error(e))

        if self.pupsrv.finishing.is_set():
            return True

    def init_readline(self):
        try:
            readline.read_history_file(".pupy_history")
        except Exception:
            pass
        self.init_completer()

    def cmdloop(self, intro=None):
        closed = False

        while not closed:
            try:
                cmd.Cmd.cmdloop(self, intro)
                closed = True

            except KeyboardInterrupt:
                self.stdout.write(b'\n')

            except Exception as e:
                logger.exception('cmd error: %s', e)

                msg = as_term_bytes(Error(traceback.format_exc()))
                self.redraw_line(msg)
                closed = True

    def init_completer(self):
        readline.set_pre_input_hook(self.pre_input_hook)
        readline.set_completer_delims(' \t')

    def completenames(self, text, *ignored):
        try:
            completer = self.commands.completer(
                self.pupsrv, self, self.config, text)

            return completer(text)
        except Exception as e:
            logger.exception(e)

    def pre_input_hook(self):
        # readline.redisplay()
        pass

    def emptyline(self):
        """ do nothing when an emptyline is entered """
        pass

    def do_EOF(self, arg):
        """ ignore EOF """
        self.stdout.write('\n')

    def do_help(self, arg):
        """ show this help """

        try:
            self.commands.execute(
                self.pupsrv, self, self.pupsrv.config,
                'help {}'.format(arg)
            )

        except PupyModuleUsageError as e:
            prog, message, usage = e.args
            self.display(Line(Error(message, prog)))
            self.display(usage)

        except PupyModuleExit:
            pass

    def acquire_io(self, requirements, amount, background=False, pipe=None):

        stream = requirements != REQUIRE_NOTHING

        if requirements in (REQUIRE_REPL, REQUIRE_TERMINAL):
            if amount > 1:
                raise NotImplementedError(
                    'This UI does not support more than 1 repl or terminal'
                )

            if pipe:
                raise NotImplementedError(
                    'This UI does not support pipelining of repl or terminal'
                )

            if requirements == REQUIRE_TERMINAL:
                stdout2 = os.dup(self.stdout.fileno())
                return [
                    RawTerminal(
                        self.stdin,
                        os.fdopen(stdout2, 'wb', 0),
                        self.config.getboolean('cmdline', 'shadow_screen')
                    )
                ]
            else:
                return [
                    IOGroup(self.stdin, self.stdout, pipe=pipe)
                ]

        elif amount == 1 and not background:
            return [
                IOGroup(None, ObjectStream(self.display, stream, pipe=pipe))
            ]
        else:
            return [
                IOGroup(
                    None, ObjectStream(stream=stream, pipe=pipe)
                ) for _ in xrange(amount)
            ]

    def process(self, job, background=False, daemon=False, unique=False):
        if background or daemon:
            if not unique:
                self.pupsrv.add_job(job)

            self.display(ServiceInfo('Background job: {}'.format(job)))
            return

        job.worker_pool.join(on_interrupt=job.interrupt)

        if job.module.io not in (REQUIRE_REPL, REQUIRE_TERMINAL):
            self.summary(job)

    def summary(self, job):
        need_title = len(job) > 1
        modules = len(job.pupymodules)

        for idx, instance in enumerate(job.pupymodules):
            if not instance.stdout:
                continue

            if need_title:
                self.display(Title(str(instance.client)))

            for block in instance.stdout.getvalue():
                self.display(block, instance.stdout.is_stream)

            if idx < modules-1:
                self.display(NewLine(0))

    def display(self, text, nocrlf=False, to_bytes=False):
        with self.display_lock:
            try:
                text = as_term_bytes(text)
            except Exception as e:
                if logger.getEffectiveLevel() == logging.DEBUG:
                    logger.exception('display error: %s', e)

            self.stdout.write(text)

            if not nocrlf:
                self.stdout.write(b'\n')

    def redraw_line(self, msg=b''):
        buf = as_term_bytes(
            readline.get_line_buffer()
        )

        msg = as_term_bytes(msg)
        prompt = as_term_bytes(self.prompt)

        self.stdout.write(
            b''.join([
                STOR_CUR,
                CUR_LEFT,
                DEL_RIGHT,
                msg,
                b'\n',
                prompt,
                buf,
                LOAD_CUR
            ])
        )

        try:
            readline.redisplay()
        except Exception:
            traceback.print_exc()

    def display_srvinfo(self, msg):
        msg = colorize(b'[*] ', 'blue') + as_term_bytes(msg)
        self.redraw_line(msg)

    def display_success(self, msg):
        return self.display(Success(msg))

    def display_error(self, msg):
        return self.display(Error(msg))

    def display_warning(self, msg):
        return self.display(Warn(msg))

    def display_info(self, msg):
        return self.display(Info(msg))

    def postcmd(self, stop, line):
        readline.write_history_file('.pupy_history')
        # readline.redisplay()
        return stop

    def complete(self, text, state):
        if state == 0:
            line = readline.get_line_buffer().lstrip()

            try:
                context = CompletionContext(
                    self.pupsrv, self, self.config, self.commands
                )

                compfunc, module, args = self.commands.completer(context, line)
                self.completion_matches = compfunc(module, args, text, context)

            except Exception as e:
                if logger.getEffectiveLevel() == logging.DEBUG:
                    logger.exception('Completion error: %s', e)

        try:
            if self.completion_matches:
                return self.completion_matches[state]

        except IndexError:
            return None

    def _complete_path(self, path=None):
        "Perform completion of filesystem path."
        if not path:
            return os.listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [
            os.path.join(dirname, p)
            for p in os.listdir(tmp) if p.startswith(rest)
        ]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in os.listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_read(self, text, line, begidx, endidx):
        tab = line.split(' ', 1)
        if len(tab) >= 2:
            return self._complete_path(tab[1])


class PupyCmdLoop(object):
    def __init__(self, pupyServer):
        self.cmd = PupyCmd(pupyServer)
        self.pupysrv = pupyServer
        self.stopped = Event()

    def loop(self):
        while not self.stopped.is_set() and not self.pupysrv.finished.is_set():
            try:
                self.cmd.cmdloop()
                self.stopped.set()
            except Exception:

                time.sleep(0.1)  # to avoid flood in case of exceptions in loop
                self.cmd.intro = []

        self.pupysrv.stop()

    def stop(self):
        self.stopped.set()

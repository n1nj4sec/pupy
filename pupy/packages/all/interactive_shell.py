# -*- coding: UTF8 -*-

import sys
from subprocess import PIPE, Popen
import subprocess
from threading  import Thread
from Queue import Queue, Empty
import time
import traceback
import locale
import re
import rpyc
import os

ON_POSIX = 'posix' in sys.builtin_module_names

def write_output(out, queue):
    try:
        for c in iter(lambda: out.read(1), b""):
            queue.put(c)
        out.close()
    except Exception as e:
        print(traceback.format_exc())

def flush_loop(queue, encoding):
    try:
        stdout_write=sys.stdout.write
        stdout_flush=sys.stdout.flush
        if type(sys.stdout) is not file:
            stdout_write=rpyc.async(sys.stdout.write)
            stdout_flush=rpyc.async(sys.stdout.flush)
        while True:
            buf=b""
            while True:
                try:
                    buf+=queue.get_nowait()
                except Empty:
                    break
            if buf:
                if encoding:
                    try:
                        buf=buf.decode(encoding)
                    except Exception:
                        pass
                stdout_write(buf)
                stdout_flush()
            time.sleep(0.05)
    except Exception as e:
        print(traceback.format_exc())

def interactive_open(program=None, encoding=None):
    try:
        if program is None:
            if sys.platform=="win32":
                program="cmd.exe"
            else:
                if "SHELL" in os.environ:
                    program=os.environ["SHELL"]
                else:
                    program="/bin/sh"
                encoding=None

        fullargs=[program]
        if sys.platform=="win32":
            try:
                #couldn't find a better way, none of the following methods worked for me : kernel32.SetConsoleOutputCP(), locale.getpreferredencoding(), sys.stdout.encoding
                encoding="cp"+str(re.findall(r".*:\s*([0-9]+)",subprocess.check_output("chcp", shell=True))[0])
            except:
                pass
            if program.endswith("powershell") or program.endswith("powershell.exe"):
                fullargs=["powershell.exe", "-C", "-"] # trick to make powershell work without blocking
        if encoding is None:
            encoding=locale.getpreferredencoding()
        print "Opening interactive %s (with encoding %s)..."%(program,encoding)
        if sys.platform=="win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags = subprocess.CREATE_NEW_CONSOLE | subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            p = Popen(fullargs, stdout=PIPE, stderr=PIPE, stdin=PIPE, bufsize=0, close_fds=ON_POSIX, universal_newlines=True, startupinfo=startupinfo)
        else:
            p = Popen(fullargs, stdout=PIPE, stderr=PIPE, stdin=PIPE, bufsize=0, close_fds=ON_POSIX, universal_newlines=True)
        q = Queue()
        q2 = Queue()
        t = Thread(target=write_output, args=(p.stdout, q))
        t.daemon = True
        t.start()

        t = Thread(target=write_output, args=(p.stderr, q2))
        t.daemon = True
        t.start()

        t = Thread(target=flush_loop, args=(q, encoding))
        t.daemon = True
        t.start()

        t = Thread(target=flush_loop, args=(q2, encoding))
        t.daemon = True
        t.start()

        while True:
            line = raw_input()
            p.stdin.write(line+"\n")
            p.stdin.flush()
            if line.strip()=="exit":
                break
    except Exception as e:
        print(traceback.format_exc())

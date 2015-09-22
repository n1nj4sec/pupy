# -*- coding: UTF8 -*-

import sys
from subprocess import PIPE, Popen
from threading  import Thread
from Queue import Queue, Empty
import time
import traceback

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
				sys.stdout.write(buf)
				sys.stdout.flush()
			time.sleep(0.5)
	except Exception as e:
		print(traceback.format_exc())

def interactive_open(program=None, encoding=None):
	try:
		if program is None:
			if "win" in sys.platform.lower():
				program="cmd.exe"
				encoding="cp437"
			else:
				program="/bin/sh"
				encoding=None
		print "Opening interactive %s ... (encoding : %s)"%(program,encoding)
		p = Popen([program], stdout=PIPE, stderr=PIPE, stdin=PIPE, bufsize=0, shell=True, close_fds=ON_POSIX, universal_newlines=True)
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
			if line.strip()=="exit":
				break
	except Exception as e:
		print(traceback.format_exc())

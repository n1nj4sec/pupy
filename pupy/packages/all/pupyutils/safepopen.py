# -*- coding: utf-8 -*-

import threading
import subprocess
import time
import Queue

def read_pipe(queue, pipe):
    completed = False
    returncode = None

    while not completed:
        try:
            returncode = pipe.poll()
            completed = returncode != None
        except Exception as e:
            print('Exception: {}'.format(e))
            continue

        try:
            data = pipe.stdout.read() \
              if completed else pipe.stdout.readline()
        except Exception:
            returncode = pipe.poll()
            break

        queue.put(data)

    queue.put(returncode)

class SafePopen(object):
    def __init__(self, *popen_args, **popen_kwargs):
        self._popen_args = popen_args
        self._popen_kwargs = popen_kwargs
        self._poll_thread = None
        self._reader = None
        self._pipe = None
        self.returncode = None

    def execute(self, poll_delay=0.5):
        returncode = None
        try:
            kwargs = self._popen_kwargs
            # Setup some required arguments
            kwargs.update({
                'stdout': subprocess.PIPE,
                'bufsize': 1
            })

            self._pipe = subprocess.Popen(
                *self._popen_args,
                **kwargs
            )
        except OSError as e:
            yield "Error: {}".format(e.strerror)
            try:
                returncode = self._pipe.poll()
            except Exception:
                pass

            self.returncode = returncode if returncode != None else -e.errno
            return

        queue = Queue.Queue()
        self._reader = threading.Thread(
            target=read_pipe,
            args=(queue, self._pipe)
        )
        self._reader.start()

        while True:
            try:
                data = queue.get(timeout=0.5)
            except Queue.Empty:
                yield None
                continue

            if type(data) == int:
                self.returncode = data
                break
            else:
                yield data

    def terminate(self):
        if not self.returncode and self._pipe:
            self._pipe.terminate()

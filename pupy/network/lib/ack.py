# -*- encoding: utf-8 -*-

# Event (cond var) is simply to complex for our dumb case
# for c in ( Event, Ack ):
#     start = time.time()
#     for x in xrange(1000000):
#         a = c()
#         a.is_set()
#         a.set()
#         a.wait()
#     print c, time.time() - start
#
# <function Event at 0x7fc42a3681b8> 14.4261770248
# <class '__main__.Ack'> 3.26524806023

__all__ = ['Ack']

from threading import Lock
from time import time, sleep

class Ack(object):
    """ Dumb (and fast, and unsafe) event replacement """

    __slots__ = ('_lock', '_is_set', '_wait_lock')

    def __init__(self):
        self._lock = Lock()
        self._is_set = None
        self._wait_lock = None

    def is_set(self):
        with self._lock:
            return self._is_set is True

    def set(self):
        with self._lock:
            if self._is_set is False and self._wait_lock:
                self._wait_lock.release()

            self._is_set = True

    def wait(self, timeout=None, probe=0.5):
        if not timeout:
            with self._lock:
                if self._is_set:
                    return True

                elif self._is_set is None:
                    self._is_set = False
                    self._wait_lock = Lock()
                    self._wait_lock.acquire()

                else:
                    raise ValueError('Already in wait state!')

            self._wait_lock.acquire()

            with self._lock:
                self._wait_lock = None
                return self._is_set is True

        else:
            with self._lock:
                if self._is_set:
                    return True

            delay = 0.00005
            prev = time()
            while timeout > 0:
                sleep(delay)
                now = time()
                timeout -= now - prev
                prev = now
                delay = min(timeout, probe, delay*2)

                with self._lock:
                    if self._is_set:
                        return True

            return False

# -*- coding: utf-8 -*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------

import threading
import inspect
import ctypes
import logging

from .PupyErrors import PupyModuleError, PupyModuleExit
from .PupyConfig import PupyConfig
from .PupyOutput import Info, Warn
from .PupyTriggers import ON_JOB_EXIT, event

import rpyc

#original code for interruptable threads from http://tomerfiliba.com/recipes/Thread2/
def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    if not inspect.isclass(exctype):
        raise TypeError("Only types can be raised (not instances)")
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

class Thread(threading.Thread):
    def _get_my_tid(self):
        """determines this (self's) thread id"""
        if not self.isAlive():
            raise threading.ThreadError("the thread is not active")

        # do we have it cached?
        if hasattr(self, "_thread_id"):
            return self._thread_id

        # no, look for it in the _active dict
        for tid, tobj in threading._active.items():
            if tobj is self:
                self._thread_id = tid
                return tid

        raise AssertionError("could not determine the thread's id")

    def raise_exc(self, exctype):
        """raises the given exception type in the context of this thread"""
        _async_raise(self._get_my_tid(), exctype)

    def stop(self):
        """raises SystemExit in the context of the given thread, which should
        cause the thread to exit silently (unless caught)"""
        self.raise_exc(KeyboardInterrupt)

class ThreadPool(object):
    def __init__(self):
        self.thread_pool = []
        self.interrupt = threading.Event()

    def apply_async(self, func, args):
        t = Thread(target=func, args=args)
        t.daemon = True
        self.thread_pool.append(t)
        t.start()

    def interrupt_all(self):
        self.interrupt.set()
        for t in self.thread_pool:
            if t.isAlive():
                t.stop()

    def interrupt(self):
        self.interrupt.set()

    def join(self, timeout=5, on_interrupt=None):
        allok = True

        while True:
            try:
                if self.interrupt.is_set():
                    allok = on_interrupt()
                    break

                allok = True
                for t in self.thread_pool:
                    if t.isAlive():
                        t.join(timeout)
                        allok = False

                if allok:
                    break

            except KeyboardInterrupt:
                self.interrupt.set()

        return allok

    def all_finished(self):
        for t in self.thread_pool:
            if t.isAlive():
                return False

        return True

class PupyJob(object):
    """ a job handle a group of modules """

    def __init__(self, pupsrv, module, name, args):
        self.name = name
        self.args = args
        self.pupsrv = pupsrv
        self.handler = pupsrv.handler
        self.config = pupsrv.config or PupyConfig()
        self.pupymodules = []
        self.worker_pool = ThreadPool()
        self.started = threading.Event()
        self.error = None
        self.jid = None
        self.destroyed = False
        self.id = None
        self.interrupted = False

    @property
    def module(self):
        return type(self.pupymodules[0])

    @property
    def clients(self):
        return [
            x.client for x in self.pupymodules
        ]

    def add_module(self, mod):
        self.pupymodules.append(mod)

    def stop(self):
        for p in self.pupymodules:
            p.stop_daemon()

        self.pupsrv.del_job(self.jid)
        self.interrupt()

    def module_worker(self, module, once):
        e = None

        try:
            module.import_dependencies()
            module.init(self.args)
            module.run(self.args)

        except PupyModuleExit as e:
            self.error = e
            return

        except PupyModuleError as e:
            self.error = e
            if not self.interrupted:
                module.error(e)

        except KeyboardInterrupt:
            pass

        except Exception as e:
            import logging
            logging.exception(e)

            self.error = e
            if not self.interrupted:
                module.error(e)

        finally:
            if not self.interrupted and once:
                module.clean_dependencies()

            module.closeio()

            if self.id is not None:
                kwargs = dict(module.client.desc)
                kwargs.update({
                    'jid': self.id,
                    'exception': e,
                    'interrupted': self.interrupted
                })

                event(ON_JOB_EXIT, module.client, self.pupsrv, **kwargs)

                if e:
                    self.pupsrv.info('<jid={}/cid={}> - error: {}'.format(self.id, module.client.id, e))
                elif self.interrupted:
                    self.pupsrv.info('<jid={}/cid={}> interrupted'.format(self.id, module.client.id))
                else:
                    self.pupsrv.info('<jid={}/cid={}> done'.format(self.id, module.client.id))

    def start(self, once=False):
        #if self.started.is_set():
        #    raise RuntimeError("job %s has already been started !"%str(self))

        for m in self.pupymodules:

            res = m.is_compatible()
            if type(res) is tuple:
                comp, comp_exp = res
            elif res is None:
                comp = True
                comp_exp = ""
            else:
                comp=res
                comp_exp = "reason not precised"

            if not comp:
                m.error("Compatibility error : %s"%comp_exp)
                continue

            self.worker_pool.apply_async(self.module_worker, (m, once))

        self.started.set()

    def interrupt(self):
        if not self.started:
            raise RuntimeError("can't interrupt. job %s has not been started"%str(self))

        if self.interrupted:
            return True

        self.interrupted = True

        #calling the interrupt method is one is defined for the module instead of killing the thread
        if hasattr(self.pupymodules[0], 'interrupt'):
            self.handler.display(Info('Sending interrupt request'))
            for m in self.pupymodules:
                m.interrupt()

            return True

        else:
            self.pupsrv.info(
                Warn('Module does not support interrupts. Resources may leak!'))
            self.worker_pool.interrupt_all()
            self.check()
            return False

    def interactive_wait(self):
        self.worker_pool.join(on_interrupt=self.interrupt)

        if self.error:
            return True

        return False

    def check(self):
        for m in self.pupymodules:
            while True:
                if not m.client:
                    break

                try:
                    m.client.conn._conn.ping(timeout=2)
                    break

                except KeyboardInterrupt:
                    continue

                except (rpyc.AsyncResultTimeout, ReferenceError, EOFError), e:
                    logging.error('connection {} seems blocked ({}), reinitialising...'.format(
                        m.client.short_name(), e))

                    try:
                        m.client.conn._conn.close()
                    except (rpyc.AsyncResultTimeout, ReferenceError, EOFError):
                        pass

                    break

    def is_finished(self):
        return self.worker_pool.all_finished()

    def free(self):
        if self.destroyed:
            return

        self.destroyed = True

        del self.pupymodules[:]
        del self.pupymodules

    def __len__(self):
        return len(self.pupymodules)

    def __str__(self):
        name = self.name
        if self.id:
            name = '{} (id={})'.format(name, self.id)
        return name

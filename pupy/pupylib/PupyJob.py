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

import time
import threading
import inspect
import ctypes
import logging
from .PupyErrors import PupyModuleError, PupyModuleExit
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
        self.thread_pool=[]

    def apply_async(self, func, args):
        t=Thread(target=func, args=args)
        t.daemon=True
        self.thread_pool.append(t)
        t.start()

    def interrupt_all(self):
        for t in self.thread_pool:
            if t.isAlive():
                t.stop()

    def join(self):
        while True:
            try:
                allok=True
                for t in self.thread_pool:
                    if t.isAlive():
                        t.join(0.5)
                        allok=False
                if allok:
                    break
            except KeyboardInterrupt:
                print "Press [ENTER] to interrupt the job"
                pass

    def all_finished(self):
        for t in self.thread_pool:
            if t.isAlive():
                return False
        return True

class PupyJob(object):
    """ a job handle a group of modules """

    def __init__(self, pupsrv, name):
        self.name=name
        self.pupsrv=pupsrv
        self.pupymodules=[]
        self.worker_pool=ThreadPool()
        self.started=threading.Event()
        self.error_happened=threading.Event()
        self.jid=None

    def add_module(self, mod):
        self.pupymodules.append(mod)

    def stop(self):
        for p in self.pupymodules:
            p.stop_daemon()
        self.pupsrv.del_job(self.jid)
        self.interrupt()

    def module_worker(self, module, args):
        try:
            module.import_dependencies()
            module.run(args)
        except PupyModuleExit as e:
            return
        except PupyModuleError as e:
            self.error_happened.set()
            module.error(str(e))
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self.error_happened.set()
            module.error(str(e))

    def start(self, args):
        #if self.started.is_set():
        #    raise RuntimeError("job %s has already been started !"%str(self))
        for m in self.pupymodules:
            try:
                margs=m.arg_parser.parse_args(args)
            except PupyModuleExit as e:
                m.error("Arguments parse error : %s"%e)
                continue
            res = m.is_compatible()
            if type(res) is tuple:
                comp, comp_exp=res
            elif res is None:
                comp=True
                comp_exp=""
            else:
                comp=res
                comp_exp="reason not precised"
            if not comp:
                m.error("Compatibility error : %s"%comp_exp)
                continue
            self.worker_pool.apply_async(self.module_worker, (m, margs))
        self.started.set()

    def interrupt(self):
        if not self.started:
            raise RuntimeError("can't interrupt. job %s has not been started"%str(self))

        #calling the interrupt method is one is defined for the module instead of killing the thread
        if hasattr(self.pupymodules[0],'interrupt'):
            for m in self.pupymodules:
                m.interrupt()
        else:
            self.worker_pool.interrupt_all()
            self.wait()

    def interactive_wait(self):
        while True:
            if self.is_finished():
                break
            time.sleep(0.1)
        if self.error_happened.is_set():
            return True
        return False

    def wait(self):
        self.worker_pool.join()
        for m in self.pupymodules:
            while True:
                if not m.client:
                    break

                try:
                    m.client.conn._conn.ping(timeout=2)
                    break
                except KeyboardInterrupt:
                    continue
                except (rpyc.AsyncResultTimeout, ReferenceError, EOFError):
                    logging.debug("connection %s seems blocked, reinitialising..."%str(m))
                    try:
                        m.client.conn._conn.close()
                    except (rpyc.AsyncResultTimeout, ReferenceError, EOFError):
                        pass

                    break

    def is_finished(self):
        return self.worker_pool.all_finished()

    def raw_result(self):
        if len(self.pupymodules)>1:
            raise AssertionError("raw_result is only available when the job contains a single module")
        m=self.pupymodules[0]
        res=m.stdout.getvalue()
        m.stdout.truncate(0)
        return res

    def result_summary(self):
        res=""
        for m in self.pupymodules:
            res+=m.formatter.format_section(str(m.client))
            gv=m.stdout.getvalue()
            res+=gv.encode('utf8', errors="replace")
            res+="\n"
            m.stdout.truncate(0)
        return res

    def __del__(self):
        for m in self.pupymodules:
            del m
        del self.pupymodules

    def get_clients_nb(self):
        return len(self.pupymodules)

    def __str__(self):
        return "< %s >"%(self.name)

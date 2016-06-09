#!/usr/bin/env python
# -*- coding: UTF8 -*-

""" This is a module to substiture some twisted functions used in obfsproxy to avoid dependencies with twisted """
import threading
import traceback
import time

def delayer_func(delay, cb, args, kwargs):
    time.sleep(delay)
    cb(*args, **kwargs)


def callLater(delay, callable, *args, **kw):
    t=threading.Thread(target=delayer_func, args=(delay, callable, args, kw))
    t.daemon=True
    t.start()

class threadDeferer(threading.Thread):
    def __init__(self, target=None, args=tuple(), kwargs={}):
        threading.Thread.__init__(self)
        self.res=None
        self.err_cb=None
        self.cb=None
        self.daemon=True
        self.__target=target
        self.__args=args
        self.__kwargs=kwargs

    def addCallback(self, func, *args):
        self.cb=func
        self.cb_args=args

    def addErrback(self, func, *args):
        self.err_cb=func
        self.err_cb_args=args
        #start the thread when the addErrback has been called, works for obfs3
        #TODO: quick and dirty, do better
        self.start()

    def run(self):
        try:
            if self.__target:
                self.res=self.__target(*self.__args, **self.__kwargs)
        except Exception as e:
            print "errBack: %s"%traceback.format_exc()
            if self.err_cb:
                self.err_cb(e, *self.err_cb_args)
        else:
            if self.cb:
                self.cb(self.res, *self.cb_args)
        finally:
            del self.__target, self.__args, self.__kwargs

    
def deferToThread(function, *args):
    return threadDeferer(target=function, args=args)


#!/usr/bin/env python
# -*- coding: UTF8 -*-

__all__=["call_later"]
import time, threading
def delayer_func(delay, cb, args, kwargs):
    time.sleep(delay)
    cb(*args, **kwargs)


def call_later(delay, callable, *args, **kw):
    t=threading.Thread(target=delayer_func, args=(delay, callable, args, kw))
    t.daemon=True
    t.start()

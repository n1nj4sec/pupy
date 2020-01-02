#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = ['call_later']

import time
import threading


def delayer_func(delay, cb, args, kwargs):
    time.sleep(delay)
    cb(*args, **kwargs)


def call_later(delay, callable, *args, **kw):
    t = threading.Thread(target=delayer_func, args=(delay, callable, args, kw))
    t.daemon = True
    t.start()

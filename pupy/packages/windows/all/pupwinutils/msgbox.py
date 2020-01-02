#!/usr/bin/env python
# -*- coding: UTF8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import ctypes
import threading

def MessageBox(text, title):
    t=threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
    t.daemon=True
    t.start()

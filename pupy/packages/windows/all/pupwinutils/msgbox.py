#!/usr/bin/env python
# -*- coding: UTF8 -*-

import ctypes
import threading

def MessageBox(text, title):
    t=threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
    t.daemon=True
    t.start()

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import mss
import threading
import time

from png import bmp_to_png

try:
    import keyboard
    from keyboard import mouse
    remote_control = True
except:
    remote_control = False

def get_screen_size():
    screenshoter = mss.mss()
    monitors = screenshoter.monitors
    del monitors[0]
    monitor=monitors[0]
    height=monitor['height']
    width=monitor['width']
    return width, height

class VideoStreamer(threading.Thread):
    def __init__(self, callback, refresh_interval=0.1, quality=75):
        threading.Thread.__init__(self)
        self.stopped = threading.Event()
        self.refresh_interval = refresh_interval
        self.quality = quality
        self.callback = callback
        self.daemon = True

    def run(self):
        screenshoter = mss.mss()
        monitors = screenshoter.monitors
        del monitors[0]
        monitor = monitors[0]
        height = monitor['height']
        width = monitor['width']

        while not self.stopped.is_set():
            try:
                scr = screenshoter.grab(monitor)
                self.callback(bmp_to_png(scr.rgb, scr.width, scr.height))
                time.sleep(self.refresh_interval)
            except:
                break

    def move(self, x, y):
        if not remote_control:
            raise "Remote control is not available"

        mouse.move(x, y)

    def click(self, x=None, y=None):
        if not remote_control:
            raise "Remote control is not available"

        if x is not None and y is not None:
            self.move(x, y)

        mouse.click()

    def kbd_send(self, *args, **kwargs):
        if not remote_control:
            raise "Remote control is not available"

        keyboard.send(*args, **kwargs)

    def kbd_write(self, *args, **kwargs):
        if not remote_control:
            raise "Remote control is not available"

        keyboard.write(*args, **kwargs)

    def key_press(self, c):
        if not remote_control:
            raise "Remote control is not available"

        keyboard.press(c)

    def key_release(self, key):
        if not remote_control:
            raise "Remote control is not available"

        keyboard.release(c)

    def stop(self):
        self.stopped.set()

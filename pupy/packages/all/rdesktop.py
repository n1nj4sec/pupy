#!/usr/bin/env python
# -*- coding: UTF8 -*-
import mss
from PIL import Image
from io import BytesIO
import threading
import time
import keyboard
from keyboard import mouse

def get_screen_size():
    screenshoter = mss.mss()
    monitors = screenshoter.enum_display_monitors()
    del monitors[0]
    monitor=monitors[0]
    height=monitor['height']
    width=monitor['width']
    return width, height



class VideoStreamer(threading.Thread):
    def __init__(self, callback, refresh_interval=0.1, quality=75):
        threading.Thread.__init__(self)
        self.stopped=threading.Event()
        self.refresh_interval=refresh_interval
        self.quality=quality
        self.callback=callback
        self.daemon=True

    def run(self):
        screenshoter = mss.mss()
        monitors = screenshoter.enum_display_monitors()
        del monitors[0]
        monitor=monitors[0]
        height=monitor['height']
        width=monitor['width']
        while not self.stopped.is_set():
            try:
                pixels=screenshoter.get_pixels(monitor)
                img= Image.frombytes('RGB', (width, height), pixels)
                bio=BytesIO()
                img.save(bio, format="jpeg", quality=self.quality)
                self.callback(bio.getvalue())
                time.sleep(self.refresh_interval)
            except:
                break

    def move(self, x, y):
        mouse.move(x, y)

    def click(self, x=None, y=None):
        if x is not None and y is not None:
            self.move(x, y)
        mouse.click()

    def kbd_send(self, *args, **kwargs):
        keyboard.send(*args, **kwargs)

    def kbd_write(self, *args, **kwargs):
        keyboard.write(*args, **kwargs)

    def key_press(self, c):
        keyboard.press(c)

    def key_release(self, key):
        keyboard.release(c)


    def stop(self):
        self.stopped.set()


if __name__=="__main__":
    #vs=VideoStreamer(cb)
    #vs.start()
    d=get_screen_jpg()
    with open("test.jpg", 'wb') as f:
        f.write(d)

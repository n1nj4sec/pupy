#!/usr/bin/env python
# -*- coding: UTF8 -*-
import mss
from PIL import Image
from io import BytesIO
import threading
import time
import pyautogui

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

    def click(self, x, y):
        pyautogui.moveTo(x, y)
        pyautogui.click()

    def key_press(self, key):
        pyautogui.press(key)

    def key_down(self, key):
        pyautogui.keyDown(key)

    def key_up(self, key):
        pyautogui.keyUp(key)

    def key_typewrite(self, key):
        pyautogui.typewrite(key)

    def key_hotkey(self, *args):
        pyautogui.hotkey(*args)

    def stop(self):
        self.stopped.set()


if __name__=="__main__":
    #vs=VideoStreamer(cb)
    #vs.start()
    d=get_screen_jpg()
    with open("test.jpg", 'wb') as f:
        f.write(d)

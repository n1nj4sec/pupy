# -*- coding: utf-8 -*-

import mss
from png import bmp_to_png

def screens():
    screenshoter = mss.mss()
    monitors = screenshoter.monitors
    return monitors[1:] if len(monitors) > 1 else monitors

def screenshot(screen=None):
    screenshoter = mss.mss()
    screenshots = []

    monitors = screens()
    if len(monitors) == 0:
        return None

    if screen is not None:
        if screen >= len(monitors):
            return None, 'the screen id does not exist'
        else:
            monitors = [monitors[screen]]

    for monitor in monitors:
        scr = screenshoter.grab(monitor)
        screenshots.append(
            bmp_to_png(scr.rgb, scr.width, scr.height)
        )

    return screenshots, None

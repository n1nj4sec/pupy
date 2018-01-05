# -*- coding: utf-8 -*-

import mss
from png import bmp_to_png

def screens():
    screenshoter = mss.mss()
    monitors = screenshoter.enum_display_monitors()
    return monitors[1:] if len(monitors) > 1 else monitors

def screenshot(screen=None):
    screenshoter = mss.mss()
    screenshots = []

    monitors = screenshoter.enum_display_monitors()
    del monitors[0]

    if len(monitors) == 0:
        return None

    if screen:
        if screen < len(monitors):
            return None, 'the screen id does not exist'
        else:
            monitors = [monitors[screen]]

    for monitor in monitors:
        screenshots.append(
            bmp_to_png(
                screenshoter.get_pixels(monitor),
                monitor['width'], monitor['height']
            )
        )

    return screenshots, None

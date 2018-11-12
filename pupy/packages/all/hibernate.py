# -*- coding: utf-8 -*-
import pupy


def sleep_time(seconds):
    try:
        pupy.sleep = int(seconds) * 3600
        return True
    except Exception:
        return False

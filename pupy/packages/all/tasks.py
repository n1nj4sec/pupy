# -*- coding: utf-8 -*-

# Wrapper around tasks module

import pupy

def list():
    return pupy.manager.status()

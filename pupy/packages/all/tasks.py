# -*- coding: utf-8 -*-

# Wrapper around tasks module

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import pupy.agent

def list():
    return pupy.manager.status()

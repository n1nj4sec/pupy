# -*- coding: utf-8 -*-

import logging

logger = logging.getLogger('pupy')
def getLogger(name):
    return logger.getChild(name)

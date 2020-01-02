# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from network.lib import getLogger as topGetLogger

logger = topGetLogger('launcher')

def getLogger(name):
    return logger.getChild(name)


__all__ = ('getLogger',)

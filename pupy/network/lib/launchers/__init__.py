# -*- encoding: utf-8 -*-

from network.lib import getLogger as topGetLogger

logger = topGetLogger('launcher')

def getLogger(name):
    return logger.getChild(name)


__all__ = (getLogger,)

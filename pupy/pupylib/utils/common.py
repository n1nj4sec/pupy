#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import os

def getLocalAndroidPath(localFolder, androidID, userName):
    '''
    For Android Only
    Returns the current local path for saving data locally
    Create folder if not exists
    '''
    localPath = os.path.join(localFolder, "{0}-{1}".format(androidID, userName))
    if not os.path.exists(localPath):
        os.makedirs(localPath)
    return localPath

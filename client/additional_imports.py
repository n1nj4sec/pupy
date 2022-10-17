from __future__ import print_function
import umsgpack
import socket
import threading
import queue
import collections
import struct
import os
import sys
import time
import traceback
import uuid
import subprocess
import imp
import hashlib
import hmac
import base64
import logging
import re
import ssl
import tempfile
import string
import datetime
import random
import shutil
import platform
import errno
import stat
import zlib
import code
import glob
import math
import binascii
import shlex
import json
import ctypes
import threading
import urllib
import getpass
import __future__
import netaddr
import urllib_auth
import http_parser
import unicodedata
import getpass

try:
    import psutil
except Exception as e:
    print("psutil: ", e)
import pyexpat
import fnmatch

try:
    import dukpy
except ImportError:
    print("dukpy not found")

try:
    import kcp
except ImportError:
    print("kcp not found")

try:
    import uidle
except ImportError:
    print("uidle not found")

import poster

if 'win' in sys.platform:
    import ctypes.wintypes

    try:
        import win_inet_pton
    except AttributeError:
        pass

    import winkerberos
else:
    import pty
    try:
        import kerberos
    except ImportError:
        print("kerberos not found")

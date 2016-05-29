#!/usr/bin/env python

# This file is part of creddump.
#
# creddump is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# creddump is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with creddump.  If not, see <http://www.gnu.org/licenses/>.

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

import sys
from framework.win32.lsasecrets import get_file_secrets

# Hex dump code from
# http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/142812

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def showUsage():
    print "usage: %s <system hive> <security hive> <Vista/7>" % sys.argv[0]
    print "\nExample (Windows Vista/7):"
    print "%s /path/to/System32/config/SYSTEM /path/to/System32/config/SECURITY true" % sys.argv[0]
    print "\nExample (Windows XP):"
    print "%s /path/to/System32/SYSTEM /path/to/System32/config/SECURITY false" % sys.argv[0]


def dump(src, length=8):
    N=0; result=''
    while src:
       s,src = src[:length],src[length:]
       hexa = ' '.join(["%02X"%ord(x) for x in s])
       s = s.translate(FILTER)
       result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
       N+=length
    return result

if len(sys.argv) < 4 or sys.argv[3] not in ["true", "false"]:
    showUsage()
    sys.exit(1)
else:
    vista = True if sys.argv[3] == "true" else False

secrets = get_file_secrets(sys.argv[1], sys.argv[2], vista)
if not secrets:
    print "Unable to read LSA secrets. Perhaps you provided invalid hive files?"
    sys.exit(1)

for k in secrets:
    print k
    print dump(secrets[k], length=16)

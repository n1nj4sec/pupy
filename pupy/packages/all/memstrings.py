#!/usr/bin/env python
# -*- coding: utf-8 -*-

import memorpy
import re
import os
import logging

def try_int(x):
    try:
        return int(x)
    except:
        return x

def iterate_strings(targets, regex=None, min_length=4, max_length=51, omit='isxr', portions=4096, nodup=True, terminate=None):
    if not targets:
        return

    if type(targets) == (str, int):
        targets = [targets]

    targets = set([try_int(x) for x in targets])

    if regex is None:
        printable = re.compile('^[\x20-\x7e]{{{},{}}}$'.format(min_length, max_length))
    else:
        printable = re.compile(regex)

    for process in memorpy.Process.list():
        if terminate is not None and terminate.is_set():
            break

        try:
            if not (
                process.get('pid') in targets or os.path.basename(process.get('name')) in targets
            ):
                continue

        except:
            continue

        strings = []
        pid = process.get('pid')
        name = process.get('name')

        try:
            mw = memorpy.MemWorker(pid=process.get('pid'))
            duplicates = set()
            for _, (cstring,) in mw.mem_search('([^\x00]+)', ftype='groups', optimizations=omit):
                if terminate is not None and terminate.is_set():
                    break

                if printable.match(cstring):
                    if nodup:
                        if cstring in duplicates:
                            continue

                        duplicates.add(cstring)

                    strings.append(cstring)
                    if len(strings) >= portions:
                        yield pid, name, strings
                        del strings[:]
        except Exception, e:
            logging.exception('MemWorker failed: %s', e)

        if strings:
            yield pid, name, strings
            del strings[:]

if __name__=="__main__":
    import sys
    for pid, strings in iterate_strings(sys.argv[1].split(',')).iteritems():
        print 'pid: ', pid
    print
    for s in strings:
            print s
    print

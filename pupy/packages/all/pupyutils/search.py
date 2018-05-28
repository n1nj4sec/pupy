#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scandir import scandir, walk
import time
import os
import re
import sys
import mmap
import threading
import rpyc
import pupy

searchThread = None #If searchThread == None, no Search Thread is running
needTerminate = threading.Event() 

def getSearchThreadStatus():
    global searchThread
    if searchThread == None:
        return False
    else:
        return searchThread.isAlive()
        
def stopSearchThread():
    '''
    Returns True if thread is stopped. 
    Otherwise returns False
    '''
    global needTerminate
    global searchThread
    if searchThread!=None:
        needTerminate.set()
        return True
    else:
        return False

class Search():
    def __init__(self, path,
                     strings=[], max_size=20000000, root_path='.', no_content=False,
                     case=False, binary=False, follow_symlinks=False):
        
        self.max_size = int(max_size)
        self.follow_symlinks = follow_symlinks
        self.no_content = no_content
        self.binary = binary
        self.case = case

        if self.case:
            i = re.IGNORECASE
        else:
            i = 0

        path = os.path.expandvars(os.path.expanduser(path))

        if os.path.isdir(path):
            root_path = path
            self.name = None
            self.path = None
        elif path.startswith('/'):
            root_path = os.path.dirname(path)
            self.name = re.compile(os.path.basename(path), i)
            self.path = None
        elif '/' in path:
            self.path = re.compile(path, i)
            self.name = None
        else:
            self.name = re.compile(path, i)
            self.path = None

        self.strings = [
            re.compile(string, i) for string in strings
        ]

        if root_path == '.':
            self.root_path = os.getcwd()
        else:
            self.root_path = root_path

    def search_string(self, path, size):
        try:
            with open(path, 'rb') as f:
                m = mmap.mmap(f.fileno(), size, access=mmap.ACCESS_READ)
                try:
                    if not self.binary:
                        sample_size = min(size, 4096)
                        sample = m[:sample_size]
                        sample_zeros = len([ x for x in sample if ord(x) == '\x00' ])
                        if not sample_zeros in (0, sample_size/2):
                            return

                    for string in self.strings:
                        for match in string.finditer(m):
                            yield match.group()
                finally:
                    m.close()

        except Exception, e:
            pass

    def scanwalk(self, path, followlinks=False):

        ''' lists of DirEntries instead of lists of strings '''
        global needTerminate
        try:
            for entry in scandir(path):
                if needTerminate.isSet()==True:
                    break

                any_file = not self.name or self.path

                if (
                    (self.name and self.name.match(entry.name)) or
                    (self.path and self.path.match(entry.path)) or
                    any_file
                ):
                    if not self.strings or not (self.strings and entry.is_file() ):
                        if not any_file:
                            yield entry.path
                    else:
                        size = entry.stat().st_size
                        if size > self.max_size:
                            continue

                        for string in self.search_string(entry.path, min(size, self.max_size)):
                            if string:
                                if self.no_content:
                                    yield entry.path
                                    break
                                else:
                                    yield (entry.path, string)

                if entry.is_dir(follow_symlinks=followlinks):
                    for res in self.scanwalk(entry.path):
                        yield res

        # try / except used for permission denied
        except Exception, e:
            pass

    def run(self):
        if os.path.isfile(self.root_path):
            for res in self.search_string(self.root_path):
                try:
                    res = res.encode('utf-8')
                    yield '%s > %s' % (self.root_path, res)
                except:
                    pass

        else:
            for files in self.scanwalk(self.root_path, followlinks=self.follow_symlinks):
                yield files

    def _run_thread(self, on_data, on_completed):
        global needTerminate
        global searchThread
        for result in self.run():
            try:
                on_data(result)
            except:
                break

        on_completed()
        searchThread = None #No thread is running anymore
        needTerminate.clear() #Reset value for next Search thread

    def run_cb(self, on_data, on_completed, daemon=False):
        '''
        Return True if correctly started. 
        Otherwise returns False (e.g. thread already running)
        '''
        global searchThread
        global needTerminate
        if getSearchThreadStatus() == True:
            #A Search thread is running, impossible to create another one yet
            return False
            
        needTerminate = threading.Event() 

        on_data = rpyc.async(on_data)
        on_completed = rpyc.async(on_completed)

        searchThread = threading.Thread(target=self._run_thread, args=(on_data, on_completed))
        searchThread.daemon = daemon
        searchThread.start()
        return True



#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scandir import scandir, walk
import time
import os
import re
import sys

class Search():
    def __init__(self, files_extensions='', max_size=20000000, check_content=False, root_path='.', search_str=[]):
        # By default max size is 20 Mo
        self.max_size = max_size
        self.files_extensions = files_extensions
        self.check_content = check_content
        if root_path == '.':
            self.root_path = os.getcwd()
        else:
            self.root_path = root_path
        self.search_str = search_str

    def search_string(self, path):
        buffer = None
        try:
            with open(path, 'rb') as f:    
                while True:
                    buffer = f.read(4096)
                    if buffer:
                        for string in self.search_str:
                            # no case sensitive on regex
                            indexes = [m.start() for m in re.finditer(string, buffer, flags=re.IGNORECASE)]
                            for i in indexes:
                                # return the entire line
                                yield buffer[i:].strip().split('\n')[0]
                    else:
                        break
        except:
            pass

    def scanwalk(self, path, followlinks=False):
        
        ''' lists of DirEntries instead of lists of strings '''
        
        dirs, nondirs = [], []
        try:
            for entry in scandir(path):
                # check if the file contains our pattern
                for s in self.search_str:
                    if entry.name.lower().find(s) != -1:
                        yield '%s' % entry.path

                # if directory, be recursive
                if entry.is_dir(follow_symlinks=followlinks):
                    for res in self.scanwalk(entry.path):
                        yield res
               
               # check inside the file to found our pattern
                else:
                    if self.max_size > entry.stat(follow_symlinks=False).st_size:
                        if entry.name.endswith(self.files_extensions):
                            if self.check_content:
                                for res in self.search_string(entry.path):
                                    try:
                                        res = res.encode('utf-8')
                                        yield '%s > %s' % (entry.path, res)
                                    except:
                                        pass

        # try / except used for permission denied 
        except:
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
            for files in self.scanwalk(self.root_path):
                yield files

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

    def search_string(self, path, search_str):
        buffer_size = 4096
        buffer = None
        try:
            with open(path, 'rb') as f:    
                while True:
                    buffer = f.read(buffer_size)
                    if buffer:
                        for string in search_str:
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
                if entry.is_dir(follow_symlinks=followlinks):
                    dirs.append(entry)
                else:
                    if self.max_size > entry.stat(follow_symlinks=False).st_size:
                        if entry.name.endswith(self.files_extensions):
                            nondirs.append(entry)
            yield path, dirs, nondirs
        # try / except used for permission denied 
        except:
            pass
        
        for dir in dirs:
            for res in self.scanwalk(dir.path, followlinks=followlinks):
                yield res

    def run(self):
        for root, dirs, files in self.scanwalk(self.root_path):
            for f in files:
                # such as find command
                for s in self.search_str:
                    if f.name.lower().find(s) != -1:
                        yield 'File: %s\n\n' % os.path.join(root, f.name)

                # such as grep command
                if self.check_content:
                    for res in self.search_string(os.path.join(root, f.name), self.search_str):
                        try:
                            res = res.encode('utf-8')
                            yield 'File: %s > %s\n\n' % (os.path.join(root, f.name), res)
                        except:
                            pass
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, os.path, logging
import compileall

def get_load_module_code(code, modulename):
    loader="""
import imp, sys
fullname={}
mod = imp.new_module(fullname)
mod.__file__ = "<bootloader>\\%s" % fullname
exec {} in mod.__dict__
sys.modules[fullname]=mod
    """.format(repr(modulename),repr(code))
    return loader

def gen_package_pickled_dic(path, module_name):
    modules_dic = {}
    start_path = module_name.replace(".", "/")
    search_path = os.path.dirname(path)
    module_dir = os.path.join(search_path, start_path)

    if os.path.isdir(path):
        compileall.compile_dir(os.path.relpath(module_dir), force=True)
        for root, dirs, files in os.walk(module_dir):
            to_embedd = set()
            for f in files:
                base, ext = os.path.splitext(f)
                if base+'.pyc' in files and not ext in ('.pyc', '.pyo'):
                    continue
                elif base+'.pyo' in files and not ext == '.pyo':
                    continue
                else:
                     to_embedd.add(f)

            for f in to_embedd:
                module_code=""
                with open(os.path.join(root,f),'rb') as fd:
                    module_code=fd.read()
                modprefix = root[len(search_path.rstrip(os.sep))+1:]
                modpath = os.path.join(modprefix,f).replace("\\","/")
                modules_dic[modpath]=module_code

    elif os.path.isfile(path):
        ext=path.rsplit(".",1)[1]
        module_code=""
        with open(path,'rb') as f:
            module_code=f.read()
        cur=""
        for rep in start_path.split("/")[:-1]:
            if not cur+rep+"/__init__.py" in modules_dic:
                modules_dic[rep+"/__init__.py"]=""
            cur+=rep+"/"

        modules_dic[start_path+"."+ext]=module_code

    if not modules_dic:
       raise NameError("path %s not found"%path)
    return modules_dic

def wrap_try_except(code):
    full_code="try:\n"
    for line in code.split("\n"):
        full_code+="\t"+line+"\n"
    full_code+="except Exception:\n\tpass\n"
    return full_code

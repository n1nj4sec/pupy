#!/usr/bin/env python
# -*- coding: UTF8 -*-

import os, os.path, logging

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
    modules_dic={}
    start_path=module_name.replace(".", "/")
    search_path=os.path.dirname(path)
    logging.info("embedding %s ..."%os.path.join(search_path, start_path))
    #TODO: remove comments from python files || compile to .pyc to make payloads lighter
    if os.path.isdir(path):
        for root, dirs, files in os.walk(os.path.join(search_path, start_path)):
            for f in files:
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

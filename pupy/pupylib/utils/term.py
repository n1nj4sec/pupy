#!/usr/bin/env python
# -*- coding: UTF8 -*-

import random

def colorize(s, color):
    if s is None:
        return ""
    s=str(s)
    res=s
    COLOR_STOP="\033[0m"
    if color.lower()=="random":
        color=random.choice(["blue","red","green","yellow"])
    if color.lower()=="blue":
        res="\033[34m"+s+COLOR_STOP
    if color.lower()=="red":
        res="\033[31m"+s+COLOR_STOP
    if color.lower()=="green":
        res="\033[32m"+s+COLOR_STOP
    if color.lower()=="yellow":
        res="\033[33m"+s+COLOR_STOP
    if color.lower()=="grey":
        res="\033[37m"+s+COLOR_STOP
    if color.lower()=="darkgrey":
        res="\033[1;30m"+s+COLOR_STOP
    return res

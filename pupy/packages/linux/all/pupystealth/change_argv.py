#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Modifications: Nicolas VERDIER (contact@n1nj4.eu)
# Original author is unknown
# source : I received the original version of this code from a private message on reddit
import ctypes
import os
import sys

class Stat():
    def add(self, pid, comm, state, ppid, pgrp, session, tty_nr, tpgid, flags, minflt, cminflt, majflt, cmajflt, utime, stime, cutime, cstime, priority, nice, num_threads, itrealvalue, starttime, vsize, rss, rsslim, startcode, endcode, startstack, kstkesp, kstkeip, signal, blocked, sigignore, sigcatch, wchan, nswap, cnswap, exit_signal, processor, rt_priority, policy, delayacct_blkio_ticks, guest_time, cguest_time, start_data, end_data, start_brk, arg_start, arg_end, env_start, env_end, exit_code):
	self.argv  = (int(arg_start), int(arg_end))
	self.env = (int(env_start), int(env_end))


def parse_proc_stat():
    with open("/proc/self/stat", "r") as fh:# ?3.5+ specific
        a = tuple(fh.read().split())
    s = Stat()
    s.add(*a)
    return s


def memcpy(dest, source):
    start, end = dest
    if len(source) > end - start:
        raise ValueError("ma jel")
    ptr = ctypes.POINTER(ctypes.c_char)
    idx = 0
    write = ''
    for tmp in range(start, end-1):
        a = ctypes.cast(tmp, ptr)
        if idx>=len(source):
            write = "\x00"
        else:
            write = source[idx]
        a.contents.value = write
        idx +=1

def change_argv(argv="/bin/bash", env=""):
        info = parse_proc_stat()
        memcpy(info.argv, argv) #clean argv
        memcpy(info.env, env) #clean environ

if __name__=="__main__":
	print "pid: %s"%os.getpid()
	change_argv(argv="[kworker/2:0]")
	import time
	while True:
		time.sleep(1)
	

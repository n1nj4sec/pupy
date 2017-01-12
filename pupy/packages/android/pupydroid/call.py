#!/usr/bin/env python
# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

from jnius import autoclass, PythonJavaClass, java_method, cast

def getCallDetails():
    '''
    '''
    calls = []
    CallLog = autoclass('android.provider.CallLog')
    Calls = autoclass('android.provider.CallLog$Calls')
    PythonActivity = autoclass('org.renpy.android.PythonService')
    cursor = PythonActivity.mService.getContentResolver().query(Calls.CONTENT_URI, None, None, None, Calls.DATE+" DESC")
    callsCount = cursor.getCount();
    if callsCount > 0:
        while cursor.moveToNext():
            callType = "?"
            phNum = cursor.getString(cursor.getColumnIndex(Calls.NUMBER))
            callTypeCode = cursor.getString(cursor.getColumnIndex(Calls.TYPE))
            callDate = cursor.getString(cursor.getColumnIndex(Calls.DATE))
            callDuration = cursor.getString(cursor.getColumnIndex(Calls.DURATION))
            calls.append({'phNum':phNum,'callTypeC':callTypeCode,'callDate':callDate, 'callDuration':callDuration})
    cursor.close()
    return calls

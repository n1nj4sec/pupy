#!/usr/bin/env python
# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

from jnius import autoclass, PythonJavaClass, java_method, cast

def getAndroidID():
    '''
    Returns None if an error
    '''
    try:
        pythonActivity = autoclass('org.renpy.android.PythonService')
        settingsSecure = autoclass('android.provider.Settings$Secure')
        androidId = settingsSecure.getString(pythonActivity.mService.getContentResolver(), settingsSecure.ANDROID_ID)
        return androidId
    except Exception,e:
        return None

def getPhoneNumber():
    '''
    Returns None if an error
    '''
    try:
        mContext = autoclass('android.content.Context')
        pythonActivity = autoclass('org.renpy.android.PythonService')
        telephonyManager = cast('android.telephony.TelephonyManager', pythonActivity.mService.getSystemService(mContext.TELEPHONY_SERVICE))
        phoneNumber = telephonyManager.getLine1Number()
        return phoneNumber
    except Exception,e:
        return None
        
def getDeviceId():
    '''
    Returns the unique device ID, for example, the IMEI for GSM and the MEID or ESN for CDMA phones. 
    Otherwise, returns None
    Requires Permission: READ_PHONE_STATE
    '''
    try:
        mContext = autoclass('android.content.Context')
        pythonActivity = autoclass('org.renpy.android.PythonService')
        telephonyManager = cast('android.telephony.TelephonyManager', pythonActivity.mService.getSystemService(mContext.TELEPHONY_SERVICE))
        deviceId = telephonyManager.getDeviceId()
        return deviceId
    except Exception,e:
        return None

def getSimCountryIso():
    '''
    Returns the ISO country code equivalent for the SIM provider's country code
    Otherwise, returns None
    Since it is the sim code it also should not change when traveling to other countries.
    '''
    try:
        mContext = autoclass('android.content.Context')
        pythonActivity = autoclass('org.renpy.android.PythonService')
        telephonyManager = cast('android.telephony.TelephonyManager', pythonActivity.mService.getSystemService(mContext.TELEPHONY_SERVICE))
        simCountryIso = telephonyManager.getSimCountryIso()
        return simCountryIso
    except Exception,e:
        return None

def getNetworkCountryIso():
    '''
    Returns the ISO country code equivalent of the current registered operator's MCC (Mobile Country Code). 
    Otherwise, returns None
    Availability: Only when user is registered to a network. Result may be unreliable on CDMA networks (use getPhoneType() to determine if on a CDMA network).
    See https://developer.android.com/reference/android/telephony/TelephonyManager.html#getNetworkCountryIso()
    '''
    try:
        mContext = autoclass('android.content.Context')
        pythonActivity = autoclass('org.renpy.android.PythonService')
        telephonyManager = cast('android.telephony.TelephonyManager', pythonActivity.mService.getSystemService(mContext.TELEPHONY_SERVICE))
        networkCountryIso = telephonyManager.getNetworkCountryIso()
        return networkCountryIso
    except Exception,e:
        return None
        
def getSimInfo():
    '''
    Returns 0 if none of voice, sms, data is not supported
    Returns 1 when there is a sim card
    Returns 2 when there is a sim card
    Returns None if an error
    --> Needs API level 23 <--
    '''
    try:
        mContext = autoclass('android.content.Context')
        pythonActivity = autoclass('org.renpy.android.PythonService')
        telephonyManager = cast('android.telephony.TelephonyManager', pythonActivity.mService.getSystemService(mContext.TELEPHONY_SERVICE))
        phoneCount = telephonyManager.getPhoneCount()
        return phoneCount
    except Exception,e:
        return None

def getNetworkOperatorName():
    '''
    Returns the alphabetic name of current registered operator
    Returns None if an error
    '''
    try:
        mContext = autoclass('android.content.Context')
        pythonActivity = autoclass('org.renpy.android.PythonService')
        telephonyManager = cast('android.telephony.TelephonyManager', pythonActivity.mService.getSystemService(mContext.TELEPHONY_SERVICE))
        networkOperatorName = telephonyManager.getNetworkOperatorName()
        return networkOperatorName
    except Exception,e:
        return None
        
def getSimState():
    '''
    Returns a string indicating the state of the default SIM card
    Returns None if an error
    '''
    try:
        status="?"
        mContext = autoclass('android.content.Context')
        pythonActivity = autoclass('org.renpy.android.PythonService')
        TelephonyManager = autoclass('android.telephony.TelephonyManager')
        telephonyManager = cast('android.telephony.TelephonyManager', pythonActivity.mService.getSystemService(mContext.TELEPHONY_SERVICE))
        simState = telephonyManager.getSimState()
        if simState == TelephonyManager.SIM_STATE_UNKNOWN:
            status = "unknown"
        elif simState == TelephonyManager.SIM_STATE_ABSENT:
            status = "absent"
        elif simState == TelephonyManager.SIM_STATE_PIN_REQUIRED:
            status = "pin_required"
        elif simState == TelephonyManager.SIM_STATE_PUK_REQUIRED:
            status = "puk_required"
        elif simState == TelephonyManager.SIM_STATE_NETWORK_LOCKED:
            status = "network_locked"
        elif simState == TelephonyManager.SIM_STATE_READY:
            status = "ready"
        return status
    except Exception,e:
        return None
        
def isNetworkRoaming():
    '''
    Returns true if the device is considered roaming on the current network, for GSM purposes.
    Returns None if an error
    Availability: Only when user registered to a network. 
    '''
    try:
        mContext = autoclass('android.content.Context')
        pythonActivity = autoclass('org.renpy.android.PythonService')
        telephonyManager = cast('android.telephony.TelephonyManager', pythonActivity.mService.getSystemService(mContext.TELEPHONY_SERVICE))
        isNetworkRoaming = telephonyManager.isNetworkRoaming()
        return isNetworkRoaming
    except Exception,e:
        return None

def isWiFiEnabled():
    '''
    Returns None if an error
    '''
    try:
        mContext = autoclass('android.content.Context')
        pythonActivity = autoclass('org.renpy.android.PythonService')
        wifiManager = cast('android.net.wifi.WifiManager', pythonActivity.mService.getSystemService(mContext.WIFI_SERVICE))
        return wifiManager.isWifiEnabled()
    except Exception,e:
        return None

def isWiFiConnected():
    mContext = autoclass('android.content.Context')
    pythonActivity = autoclass('org.renpy.android.PythonService')
    connectivityManager = autoclass('android.net.ConnectivityManager')
    cManager = cast('android.net.ConnectivityManager', pythonActivity.mService.getSystemService(mContext.CONNECTIVITY_SERVICE))
    networkInfo = cManager.getNetworkInfo(connectivityManager.TYPE_WIFI)
    return networkInfo.isConnected()

def isVPNConnected():
    mContext = autoclass('android.content.Context')
    pythonActivity = autoclass('org.renpy.android.PythonService')
    connectivityManager = autoclass('android.net.ConnectivityManager')
    cManager = cast('android.net.ConnectivityManager', pythonActivity.mService.getSystemService(mContext.CONNECTIVITY_SERVICE))
    try:
        networkInfo = cManager.getNetworkInfo(connectivityManager.TYPE_VPN)
    except Exception, e:
        return False
    return networkInfo.isConnected()

def getInfoBuild():
    '''
    Returns {'deviceName': , 'manufacturer':, 'model':, 'product': , 'bootloaderVersion':, 'hardware':, 'serial':, 'radioVersion':,  'release':}
    Returns a list of None for each attribut if an error
    '''
    try:
        build = autoclass('android.os.Build')
        version = autoclass('android.os.Build$VERSION')
        deviceName = build.DEVICE
        manufacturer = build.MANUFACTURER
        model = build.MODEL
        product = build.PRODUCT
        bootloaderVersion = build.BOOTLOADER
        hardware = build.HARDWARE
        try:
            serial = build.SERIAL
        except Exception,e:
            serial = None
        radioVersion = build.getRadioVersion()
        return {'deviceName':deviceName, 'manufacturer':manufacturer, 'model':model, 'product': product, 'bootloaderVersion':bootloaderVersion, 'hardware':hardware, 'serial':serial, 'radioVersion':radioVersion, 'release':"{0} ({1})".format(version.RELEASE, version.CODENAME)}
    except Exception, e:
        return {'deviceName':None      , 'manufacturer':None        , 'model':None , 'product': None   , 'bootloaderVersion':None             , 'hardware':None     , 'serial':None , 'radioVersion':None,         'release':None}


def getBatteryStats():
    '''
    Returns None if an error
    returns {'percentage': 99.0, 'isCharging': True}
    '''
    try:
        from plyer import battery
        return battery.status
    except Exception,e:
        return None

def getMobileNetworkType():
    '''
    Returns info about current mobile connection
    For mobile type Only (not for WiFi)
    If not using mobile connection or an error, returns None
    Return {'info':info, 'fast',fast}
        - Info: string
        - fast: True, False or None if unknow
    Help: https://gist.github.com/emil2k/5130324
    '''
    info, fast = "Error!", False
    try:
        mContext = autoclass('android.content.Context')
        pythonActivity = autoclass('org.renpy.android.PythonService')
        connectivityManager = autoclass('android.net.ConnectivityManager')
        telephonyManager = autoclass("android.telephony.TelephonyManager")
        cManager = cast('android.net.ConnectivityManager', pythonActivity.mService.getSystemService(mContext.CONNECTIVITY_SERVICE))
        activeNetworkInfo = cManager.getActiveNetworkInfo()
        cType = activeNetworkInfo.getType()
        cSubType = activeNetworkInfo.getSubtype()
        if cType != connectivityManager.TYPE_MOBILE:
            return None
        if cSubType == telephonyManager.NETWORK_TYPE_1xRTT:
            info = "1xRTT: 50-100 kbps"
            fast = False
        if cSubType == telephonyManager.NETWORK_TYPE_CDMA:
            info = "CDMA: 14-64 kbps"
            fast = False
        if cSubType == telephonyManager.NETWORK_TYPE_EDGE:
            info = "EDGE: 50-100 kbps"
            fast = False
        if cSubType == telephonyManager.NETWORK_TYPE_EVDO_0:
            info = "EVDO_0: 400-1000 kbps"
            fast = True
        if cSubType == telephonyManager.NETWORK_TYPE_EVDO_A:
            info = "EVDO_A: 600-1400 kbps"
            fast = True
        if cSubType == telephonyManager.NETWORK_TYPE_GPRS:
            info = "GPRS: 100 kbps"
            fast = False
        if cSubType == telephonyManager.NETWORK_TYPE_HSDPA:
            info = "HSDPA: 2-14 Mbps"
            fast = True
        if cSubType == telephonyManager.NETWORK_TYPE_HSPA:
            info = "HSPA: 700-1700 kbps"
            fast = True
        if cSubType == telephonyManager.NETWORK_TYPE_HSUPA:
            info = "HSUPA: 1-23 Mbps"
            fast = True
        if cSubType == telephonyManager.NETWORK_TYPE_UMTS:
            info = "UMTS: 400-7000 kbps"
            fast = True
        if cSubType == telephonyManager.NETWORK_TYPE_EHRPD: #API level 11
            info = "EHRPD: 1-2 Mbps"
            fast = True
        if cSubType == telephonyManager.NETWORK_TYPE_EVDO_B: #API level 9
            info = "EVDO_B: 5 Mbps"
            fast = True
        if cSubType == telephonyManager.NETWORK_TYPE_HSPAP: #API level 13
            info = "HSPAP: 10-20 Mbps"
            fast = True
        if cSubType == telephonyManager.NETWORK_TYPE_IDEN: #API level 8
            info = "IDEN: 25 kbps"
            fast = False
        if cSubType == telephonyManager.NETWORK_TYPE_LTE: #API level 11
            info = "LTE: 10+ Mbps"
            fast = True
        if cSubType == telephonyManager.NETWORK_TYPE_UNKNOWN:
            info = "UNKNOWN: ?"
            fast = None
        return {'info':info, 'fast':fast}
    except Exception,e:
        return {'info':info, 'fast':fast}

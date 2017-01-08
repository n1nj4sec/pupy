#!/usr/bin/env python
# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

import jnius
from jnius import autoclass, PythonJavaClass, java_method, cast

def getAndroidID():
    pythonActivity = autoclass('org.renpy.android.PythonService')
    settingsSecure = autoclass('android.provider.Settings$Secure')
    androidId = settingsSecure.getString(pythonActivity.mService.getContentResolver(), settingsSecure.ANDROID_ID)
    return androidId
    
def getPhoneNumber():
    mContext = autoclass('android.content.Context')
    pythonActivity = autoclass('org.renpy.android.PythonService')
    telephonyManager = cast('android.telephony.TelephonyManager', pythonActivity.mService.getSystemService(mContext.TELEPHONY_SERVICE))
    phoneNumber = telephonyManager.getLine1Number();
    return phoneNumber
    
def isWiFiEnabled():
    mContext = autoclass('android.content.Context')
    pythonActivity = autoclass('org.renpy.android.PythonService')
    wifiManager = cast('android.net.wifi.WifiManager', pythonActivity.mService.getSystemService(mContext.WIFI_SERVICE))
    return wifiManager.isWifiEnabled()
    
def isWiFiConnected():
    mContext = autoclass('android.content.Context')
    pythonActivity = autoclass('org.renpy.android.PythonService')
    connectivityManager = autoclass('android.net.ConnectivityManager')
    cManager = cast('android.net.ConnectivityManager', pythonActivity.mService.getSystemService(mContext.CONNECTIVITY_SERVICE))
    networkInfo = cManager.getNetworkInfo(connectivityManager.TYPE_WIFI);
    return networkInfo.isConnected()
    
def isVPNConnected():
    mContext = autoclass('android.content.Context')
    pythonActivity = autoclass('org.renpy.android.PythonService')
    connectivityManager = autoclass('android.net.ConnectivityManager')
    cManager = cast('android.net.ConnectivityManager', pythonActivity.mService.getSystemService(mContext.CONNECTIVITY_SERVICE))
    try:
        networkInfo = cManager.getNetworkInfo(connectivityManager.TYPE_VPN);
    except Exception, e:
        return False 
    return networkInfo.isConnected()
    
def getInfoBuild():
    build = autoclass('android.os.Build')
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
    return {'deviceName':deviceName, 'manufacturer':manufacturer, 'model':model, 'product': product, 'bootloaderVersion':bootloaderVersion, 'hardware':hardware, 'serial':serial, 'radioVersion':radioVersion}
    
    
    
    
    
    

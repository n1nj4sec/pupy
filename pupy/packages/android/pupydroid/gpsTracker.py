#Author: @bobsecq
#Contributor(s):

from jnius import autoclass, cast
from plyer import gps
from time import sleep
import os, datetime
from threading import Thread, Event
import jnius

GPSTRACKER_THREAD  = None
TRACES = []
CURRENT_LAT, CURRENT_LON = None, None

def __getLocation__(**kwargs):
    '''
    This function is called by configure for setting current GPS location in global variables
    Info: The on_location and on_status callables might be called from another thread than the thread used for creating the GPS object.
    See https://plyer.readthedocs.io/en/latest/
    '''
    global CURRENT_LAT
    global CURRENT_LON
    if kwargs is not None:
        #print "__getLocation__ old:{0},{1}".format(CURRENT_LAT, CURRENT_LON)
        CURRENT_LAT=kwargs['lat']
        CURRENT_LON=kwargs['lon']
        #print "__getLocation__ new:{0},{1}".format(kwargs['lat'], kwargs['lon'])

class GpsTracker(Thread):    
    
    def __init__(self, period=15, inMemory=False):
        '''
        '''
        Thread.__init__(self)
        gps.configure(on_location=__getLocation__)
        self.stopFollow=False
        self.period=period
        self.inMemory=inMemory
        self.filename = "keflfjezomef.csv"
        self.Context = autoclass('android.content.Context')
        self.PythonActivity = autoclass('org.renpy.android.PythonService')
        self.LocationManager = autoclass('android.location.LocationManager')
        
    def enable(self):
        '''
        '''
        gps.start()
        
    def disable(self):
        '''
        '''
        gps.stop()
        
    def stop(self):
        '''
        '''
        self.stopFollow=True
        
    def isGPSenabled(self):
        '''
        '''
        locationManager = cast('android.location.LocationManager', self.PythonActivity.mService.getSystemService(self.Context.LOCATION_SERVICE))
        isGPSEnabled = locationManager.isProviderEnabled(self.LocationManager.GPS_PROVIDER)
        return isGPSEnabled
    
    def isNetworkProviderEnabled(self):
        '''
        '''
        locationManager = cast('android.location.LocationManager', self.PythonActivity.mService.getSystemService(self.Context.LOCATION_SERVICE))
        isNetworkProviderEnabled = locationManager.isProviderEnabled(self.LocationManager.NETWORK_PROVIDER)
        return isNetworkProviderEnabled
    
    def getCurrentLocation(self):
        '''
        '''
        global CURRENT_LAT
        global CURRENT_LON
        return CURRENT_LAT, CURRENT_LON
       
    def follow(self):
        global TRACES
        self.enable()
        lastLat, lastLon = None, None 
        if self.inMemory==False:
            if os.path.isfile(self.filename) == False:
                f = open(self.filename,'w')
                f.write("date,latitude,longitude\n")
                f.close()
        while self.stopFollow == False:
            lat, lon = self.getCurrentLocation()
            #print "follow current:{0},{1}".format(lat, lon)
            if (lat!=None and lon!=None) and (lastLat!=lat or lastLon!=lon):
                #print "follow modified:{0},{1}".format(lat, lon)
                if self.inMemory==False:
                    f = open(self.filename,'a+')
                    f.write("{0},{1},{2}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), lat, lon))
                    f.close()
                else:
                    TRACES.append([datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), lat, lon])
            lastLat, lastLon = lat, lon
            sleep(self.period)
        self.disable()
        jnius.detach() #For fixing a BUG, see https://github.com/kivy/pyjnius/issues/107
            
    def run(self):
        self.stopFollow=False
        self.follow()
        
    def isFollowing(self):
        if self.stopFollow==True:
            return False
        else:
            return True
            

def startGpsTracker(period):
    '''
    '''
    global GPSTRACKER_THREAD
    if GPSTRACKER_THREAD == None or GPSTRACKER_THREAD.isFollowing()==False:
        gpsTracker = GpsTracker(period=period)
        gpsTracker.start()
        GPSTRACKER_THREAD=gpsTracker
        return True
    else:
        return False

def stopGpsTracker():
    '''
    '''
    global GPSTRACKER_THREAD
    if GPSTRACKER_THREAD == None:
        return False
    if GPSTRACKER_THREAD.isFollowing()==False:
        return False
    else:
        GPSTRACKER_THREAD.stop()
        #print "Joining with GPS tracking thread..."
        GPSTRACKER_THREAD.join()
        #print "Thread Finished"
        return True
   
def dumpGpsTracker():
    '''
    When inMeory is enabled
    '''
    global TRACES
    return TRACES 

def statusGpsTracker():
    '''
    '''
    global GPSTRACKER_THREAD
    if GPSTRACKER_THREAD == None:
        return False
    elif GPSTRACKER_THREAD.isFollowing()==False:
        return False
    else:
        return True

def deleteFile():
    '''
    '''
    if GPSTRACKER_THREAD != None and GPSTRACKER_THREAD.isFollowing() == False:
        try:
            os.remove(GPSTRACKER_THREAD.filename)
        except OSError:
            return False
        return True
    else:
        return False

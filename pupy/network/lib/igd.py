# -*- coding: utf-8 -*-
# Original code from: https://github.com/hujun-open/pyigdc
# Reworked by Oleskii Shevchuk (@alxchk)
# License: MIT

__all__ = (
    'UPNPError', 'FakeSocket', 'IGDClient',
)

import socket
import urllib2
from StringIO import StringIO
from httplib import HTTPResponse
from xml.etree.ElementTree import fromstring
from urlparse import urlparse
import netaddr
import logging

def str2bool(bstr):
    return bool(int(bstr))

def getProtoId(proto_name):
    if isinstance(proto_name, int):
        if proto_name > 0 and proto_name <= 65535:
            return proto_name

    proto_name = 'IPPROTO_{}'.format(proto_name)
    if not hasattr(socket, proto_name):
        return False

    return getattr(socket, proto_name)

class UPNPError(Exception):
    def __init__(self, hcode, ucode, udes):
        """
        hcode is the http error code
        ucode is the upnp error code
        udes is the upnp error description
        """
        self.http_code = hcode
        self.code = ucode
        self.description = udes

    def __str__(self):
        return "HTTP Error Code {hc}, UPnP Error Code {c}, {d}"\
            .format(hc=self.http_code, c=self.code, d=self.description)


class FakeSocket(StringIO):
    def makefile(self, *args, **kw):
        return self


def httpparse(fp):
    socket = FakeSocket(fp.read())
    response = HTTPResponse(socket)
    response.begin()
    return response


# sendSOAP is based on part of source code from miranda-upnp.
class IGDClient(object):
    """
    UPnP IGD v1 Client class, supports all actions
    """

    UPNPTYPEDICT = {
        'NewAutoDisconnectTime': int,
        'NewIdleDisconnectTime': int,
        'NewWarnDisconnectDelay': int,
        'NewPortMappingNumberOfEntries': int,
        'NewLeaseDuration': int,
        'NewExternalPort': int,
        'NewInternalPort': int,
        'NewRSIPAvailable': str2bool,
        'NewNATEnabled': str2bool,
        'NewEnabled': str2bool,
        'FirewallEnabled': str2bool,
        'InboundPinholeAllowed': str2bool,
        'OutboundPinholeTimeout': int,
        'UniqueID': int,
        'PinholePackets': int,
        'IsWorking': str2bool,
    }

    NS = {
        'device': 'urn:schemas-upnp-org:device-1-0',
        'control': 'urn:schemas-upnp-org:control-1-0',
        'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
    }

    __slots__ = (
        'ctrlURL', 'debug', 'pprint', 'isv6', 'timeout', 'intIP',
        'igdsvc', 'available', 'pr', 'bindIP'
    )

    def __init__(
            self,
            bindIP='0.0.0.0',
            ctrlURL=None,
            service="WANIPC",
            edebug=False,
            pprint=False,
            timeout=2.0,
            available=True):
        """
        - intIP is the source address of the request packet, which implies the source interface
        - ctrlURL is the the control URL of IGD server, client will do discovery if it is None
        """

        if not available:
            self.ctrlURL = None
            return

        self.debug = edebug
        self.pprint = pprint
        self.isv6 = False
        self.timeout = timeout
        self.intIP = None

        if ctrlURL:
            self.ctrlURL = urlparse(ctrlURL)
            self.bindIP = self._getOutgoingLocalAddress(self.ctrlURL.hostname)
            self.intIP = self.bindIP
            self.isv6  = self.bindIP.version == 6
        else:
            self.ctrlURL = None
            self.bindIP = netaddr.IPAddress(bindIP)
            self.isv6  = self.bindIP.version == 6

            if self.isv6:
                self.igdsvc = "IP6FWCTL"
            else:
                self.igdsvc = "WANIPC"

            self.discovery()
            self.discovery(st='upnp:rootdevice')

        if self.available and not self.intIP:
            self.intIP = self._getOutgoingLocalAddress()

    @property
    def available(self):
        return self.ctrlURL is not None

    def enableDebug(self, d=True):
        """
        enable debug output
        """
        self.debug = d

    def enablePPrint(self, p=True):
        """
        enable pretty print for XML output
        """
        self.pprint = p

    def _getOutgoingLocalAddress(self):
        try:
            ctrlurl = urlparse(self.ctrlURL)
            remote_addr = netaddr.IPAddress(ctrlurl.hostname)
            rcon = socket.socket(
                socket.AF_INET if remote_addr.version == 4 else socket.AF_INET6,
            )
            rcon.connect((remote_addr.format(), ctrlurl.port or 1900))
            return netaddr.IPAddress(rcon.getsockname()[0])

        except:
            self.available = False
            return None

    def _get1stTagText(self, xmls, tagname_list):
        """
        return 1st tag's value in the xmls
        """
        dom = fromstring(xmls)
        r = {}
        for tagn in tagname_list:
            try:
                txt_node = dom.find('.//{}'.format(tagn))
                if txt_node is not None:
                    if tagn in self.UPNPTYPEDICT:
                        r[tagn] = self.UPNPTYPEDICT[tagn](txt_node.text)
                    else:
                        r[tagn] = txt_node.text
                else:
                    r[tagn] = None
            except:
                print"xml parse err: {tag} not found".format(tag=tagn)

        return r

    def _parseErrMsg(self, err_resp):
        """
        parse UPnP error message, err_resp is the returned XML in http body
        reurn UPnP error code and error description
        """
        dom = fromstring(err_resp)
        err_code = dom.find('.//control:errorCode', self.NS)
        err_desc = dom.find('.//control:errorDescription', self.NS)
        return (err_code.text, err_desc.text)

    def discovery(self, st='urn:schemas-upnp-org:device:InternetGatewayDevice:1'):
        """
        Find IGD device and its control URL via UPnP multicast discovery
        """
        logging.warning("Sending multicast traffic looking for IGD Devices / forwarding TCP port ...")
        if not self.isv6:
            up_disc = '\r\n'.join([
                'M-SEARCH * HTTP/1.1',
                'HOST:239.255.255.250:1900',
                'ST:{}'.format(st),
                'MX:2',
                'MAN:"ssdp:discover"'
            ]) + '\r\n' * 2

            sock = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
            except:
                pass

            sock.bind((self.bindIP.format(), 19110))
            sock.sendto(up_disc, ("239.255.255.250", 1900))

        else:
            if self.bindIP.is_link_local():
                dst_ip = "ff02::c"
            else:
                dst_ip = "ff05::c"
                up_disc = '\r\n'.join([
                    'M-SEARCH * HTTP/1.1',
                    'HOST:[{dst}]:1900'.format(dst=dst_ip),
                    'ST:upnp:rootdevice',
                    'MX:2',
                    'MAN:"ssdp:discover"'
                ]) + '\r\n' * 2

            sock = socket.socket(
                socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

            if self.debug:
                print "trying to bind to address:", self.bindIP

            socketaddr = socket.getaddrinfo(
                self.bindIP.format(), 19110)[-1:][0][-1:][0]
            sock.bind(socketaddr)
            sock.sendto(up_disc, (dst_ip, 1900))

        if self.debug:
            print "Discovery: ----- tx request -----\n " + up_disc

        sock.settimeout(self.timeout)
        try:
            data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
        except socket.error:
            return

        sock.close()

        if self.debug:
            print "Discovery: ----- rx reply -----\n " + data

        descURL = httpparse(StringIO(data)).getheader('location')
        if not descURL:
            return

        try:
            descXMLs = urllib2.urlopen(descURL, None, self.timeout).read()
        except:
            return

        self.pr = urlparse(descURL)
        baseURL = self.pr.scheme + "://" + self.pr.netloc
        dom = fromstring(descXMLs)

        if self.igdsvc == "WANIPC":
            svctype = 'urn:schemas-upnp-org:service:WANIPConnection'
        else:
            svctype = 'urn:schemas-upnp-org:service:WANIPv6FirewallControl'

        for e in dom.findall('.//device:service', self.NS):
            stn = e.find('device:serviceType', self.NS)
            if stn is not None:
                if stn.text[0:-2] == svctype:
                    cun = e.find('device:controlURL', self.NS).text
                    self.ctrlURL = baseURL + cun
                    break

        if self.debug:
            print "control URL is ", self.ctrlURL

    def AddPortMapping(self, extPort, proto, intPort, enabled=1, duration=0, intIP=None, desc='', remoteHost=''):
        upnp_method = 'AddPortMapping'
        sendArgs = {
            'NewPortMappingDescription': (desc, 'string'),
            'NewLeaseDuration': (duration, 'ui4'),
            'NewInternalClient': (intIP or self.intIP, 'string'),
            'NewEnabled': (enabled, 'boolean'),
            'NewExternalPort': (extPort, 'ui2'),
            'NewRemoteHost': (remoteHost, 'string'),
            'NewProtocol': (proto, 'string'),
            'NewInternalPort': (intPort, 'ui2')
        }

        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL, upnp_method, sendArgs
        )

    def DeletePortMapping(self, extPort, proto, remoteHost=''):
        upnp_method = 'DeletePortMapping'
        sendArgs = {
            'NewExternalPort': (extPort, 'ui2'),
            'NewRemoteHost': (remoteHost, 'string'),
            'NewProtocol': (proto, 'string')
        }

        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL, upnp_method, sendArgs
        )

    def GetExternalIP(self):
        upnp_method = 'GetExternalIPAddress'
        sendArgs = {}
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL, upnp_method, sendArgs
        )

        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "NewExternalIPAddress"
            ])

    def GetGenericPortMappingEntryAll(self):
        index = 0
        items = []
        while True:
            try:
                items.append(self.GetGenericPortMappingEntry(index))
            except:
                break

            index += 1

        return items

    def GetGenericPortMappingEntry(self, index=None, hideErr=False):
        if index is None:
            return self.GetGenericPortMappingEntryAll()

        upnp_method = 'GetGenericPortMappingEntry'
        sendArgs = {
            'NewPortMappingIndex': (index, 'ui4'),
        }

        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL, upnp_method, sendArgs, hideErr=hideErr
        )

        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "NewExternalPort", "NewRemoteHost",
                "NewProtocol", "NewInternalPort",
                "NewInternalClient", "NewPortMappingDescription",
                "NewLeaseDuration", "NewEnabled"
            ])

    def GetSpecificPortMappingEntry(self, extPort, proto, remote):
        upnp_method = 'GetSpecificPortMappingEntry'
        sendArgs = {
            'NewExternalPort': (extPort, 'ui2'),
            'NewRemoteHost': (remote, 'string'),
            'NewProtocol': (proto, 'string'),
        }

        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL, upnp_method, sendArgs
        )

        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "NewInternalPort",
                "NewInternalClient", "NewPortMappingDescription",
                "NewLeaseDuration", "NewEnabled"
            ])

    def GetNATRSIPStatus(self):
        upnp_method = 'GetNATRSIPStatus'
        sendArgs = {}
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)

        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "NewRSIPAvailable",
                "NewNATEnabled",
            ])

    def GetWarnDisconnectDelay(self):
        upnp_method = 'GetWarnDisconnectDelay'
        sendArgs = {}
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)
        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "NewWarnDisconnectDelay",
            ])

    def GetIdleDisconnectTime(self):
        upnp_method = 'GetIdleDisconnectTime'
        sendArgs = {}
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)
        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "NewIdleDisconnectTime",
            ])

    def GetAutoDisconnectTime(self):
        upnp_method = 'GetAutoDisconnectTime'
        sendArgs = {}
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)
        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "NewAutoDisconnectTime",
            ])

    def GetStatusInfo(self):
        upnp_method = 'GetStatusInfo'
        sendArgs = {}
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)
        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "NewConnectionStatus",
                "NewLastConnectionError",
                "NewUptime"
            ])

    def SetWarnDisconnectDelay(self, delay):
        upnp_method = 'SetWarnDisconnectDelay'
        sendArgs = {
            'NewWarnDisconnectDelay': (delay, 'ui4'),
        }

        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL, upnp_method, sendArgs
        )

    def SetIdleDisconnectTime(self, disconnect_time):
        upnp_method = 'SetIdleDisconnectTime'
        sendArgs = {
            'NewIdleDisconnectTime': (disconnect_time, 'ui4'),
        }

        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL, upnp_method, sendArgs
        )

    def SetAutoDisconnectTime(self, disconnect_time):
        upnp_method = 'SetAutoDisconnectTime'
        sendArgs = {
            'NewAutoDisconnectTime': (disconnect_time, 'ui4'),
        }

        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL, upnp_method, sendArgs
        )

    def ForceTermination(self):
        upnp_method = 'ForceTermination'
        sendArgs = {}
        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL, upnp_method, sendArgs
        )

    def RequestTermination(self):
        upnp_method = 'RequestTermination'
        sendArgs = {}
        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)

    def RequestConnection(self):
        upnp_method = 'RequestConnection'
        sendArgs = {}
        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)

    def GetConnectionTypeInfo(self):
        upnp_method = 'GetConnectionTypeInfo'
        sendArgs = {}
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)
        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "NewConnectionType",
                "NewPossibleConnectionTypes", ])

    def SetConnectionType(self, ctype):
        upnp_method = 'SetConnectionType'
        sendArgs = {
            'NewConnectionType': (ctype, 'string'),
        }
        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)

    def customAction(self, method_name, in_args={}, svc="WANIPConnection"):
        """
        this is for the vendor specific action
        in_args is a dict,
        svc is the IGD service,
        the format is :
            key is the argument name
            value is a two element list, 1st one is the value of arguement, 2nd
            is the UPnP data type defined in the spec. following is an example:
            {'NewPortMappingIndex': [0, 'ui4'],}

        """
        upnp_method = method_name
        sendArgs = dict(in_args)
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:{svc}:1'.format(
                svc=svc),
            self.ctrlURL,
            upnp_method,
            sendArgs
        )

        return resp_xml

    def sendSOAP(self, hostName, serviceType, controlURL, actionName,
                 actionArguments, hideErr=False):
        """
        send a SOAP request and get the response
        """
        argList = ''

        if not controlURL:
            self.discovery()

        # Create a string containing all of the SOAP action's arguments and
        # values
        for arg, (val, dt) in actionArguments.iteritems():
            argList += '<%s>%s</%s>' % (arg, val, arg)

        # Create the SOAP request
        soapBody = '<?xml version="1.0"?>' \
          '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope" ' \
          'SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' \
          '<SOAP-ENV:Body>' \
          '<m:{} xmlns:m="{}">' \
          '{}' \
          '</m:{}>' \
          '</SOAP-ENV:Body>' \
          '</SOAP-ENV:Envelope>'.format(
              actionName,
              serviceType,
              argList,
              actionName
        )

        try:
            response = urllib2.urlopen(
                urllib2.Request(controlURL, soapBody, {
                    'Content-Type': 'text/xml',
                    'SOAPAction': '"{}#{}"'.format(
                        serviceType,
                        actionName
                    )
                }))
        except urllib2.HTTPError as e:
            err_code, err_desc = self._parseErrMsg(e.read())
            raise UPNPError(e.code, err_code, err_desc)

        return response.read()

    # following are for IP6FWControl
    def GetFWStatus(self):
        upnp_method = 'GetFirewallStatus'
        sendArgs = {}
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)
        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "FirewallEnabled", "InboundPinholeAllowed"])

    def AddPinhole(
            self,
            iclient,
            rhost="",
            rport=0,
            iport=0,
            proto=65535,
            leasetime=3600):
        upnp_method = "AddPinhole"
        pid = getProtoId(proto)
        if not pid:
            print proto, " is not a supported protocol"
            return
        sendArgs = {
            "RemoteHost": (rhost, 'string'),
            "RemotePort": (rport, 'ui2'),
            "InternalClient": (iclient, 'string'),
            "InternalPort": (iport, 'ui2'),
            "Protocol": (pid, 'ui2'),
            "LeaseTime": (leasetime, 'ui4'),
        }
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)
        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "UniqueID", ])

    def GetPinholeTimeout(
            self,
            iclient="",
            rhost="",
            rport=0,
            iport=0,
            proto=65535):
        upnp_method = "GetOutboundPinholeTimeout"
        pid = getProtoId(proto)
        if not pid:
            print proto, " is not a supported protocol"
            return
        sendArgs = {
            "RemoteHost": (rhost, 'string'),
            "RemotePort": (rport, 'ui2'),
            "InternalClient": (iclient, 'string'),
            "InternalPort": (iport, 'ui2'),
            "Protocol": (pid, 'ui2'),
        }

        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)

        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "OutboundPinholeTimeout",
            ])

    def UpdatePinhole(self, uid, lease):
        upnp_method = "UpdatePinhole"
        sendArgs = {
            "UniqueID": (uid, 'ui2'),
            "NewLeaseTime": (lease, 'ui4'),
        }
        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
            self.ctrlURL,
            upnp_method,
            sendArgs
        )

    def DelPinhole(self, uid):
        upnp_method = "DeletePinhole"
        sendArgs = {
            "UniqueID": (uid, 'ui2'),
        }
        self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
            self.ctrlURL,
            upnp_method,
            sendArgs
        )

    def GetPinholePkts(self, uid):
        upnp_method = "GetPinholePackets"
        sendArgs = {
            "UniqueID": (uid, 'ui2'),
        }
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)
        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "PinholePackets",
            ])

    def CheckPinhole(self, uid):
        upnp_method = "CheckPinholeWorking"
        sendArgs = {
            "UniqueID": (uid, 'ui2'),
        }
        resp_xml = self.sendSOAP(
            self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
            self.ctrlURL,
            upnp_method,
            sendArgs)
        if resp_xml:
            return self._get1stTagText(resp_xml, [
                "IsWorking",
            ])

# https://raw.githubusercontent.com/jtriley/pystun/develop/stun/__init__.py

__all__ = (
    'stun_test',
    'get_nat_type',
    'get_ip_info',
    'get_ip'
)

import binascii
import random
import socket

__version__ = '0.1.0'

from network.lib import getLogger
log = getLogger("pystun")

STUN_SERVERS = (
    'stun.ekiga.net',
    'stun.ideasip.com',
    'stun.voiparound.com',
    'stun.voipbuster.com',
    'stun.voipstunt.com',
    'stun.voxgratia.org'
)

DEFAULTS = {
    'stun_port': 3478,
}

# stun attributes
MappedAddress = '0001'
ResponseAddress = '0002'
ChangeRequest = '0003'
SourceAddress = '0004'
ChangedAddress = '0005'
Username = '0006'
Password = '0007'
MessageIntegrity = '0008'
ErrorCode = '0009'
UnknownAttribute = '000A'
ReflectedFrom = '000B'
XorOnly = '0021'
XorMappedAddress = '8020'
ServerName = '8022'
SecondaryAddress = '8050'  # Non standard extension

# types for a stun message
BindRequestMsg = '0001'
BindResponseMsg = '0101'
BindErrorResponseMsg = '0111'
SharedSecretRequestMsg = '0002'
SharedSecretResponseMsg = '0102'
SharedSecretErrorResponseMsg = '0112'

dictAttrToVal = {'MappedAddress': MappedAddress,
                 'ResponseAddress': ResponseAddress,
                 'ChangeRequest': ChangeRequest,
                 'SourceAddress': SourceAddress,
                 'ChangedAddress': ChangedAddress,
                 'Username': Username,
                 'Password': Password,
                 'MessageIntegrity': MessageIntegrity,
                 'ErrorCode': ErrorCode,
                 'UnknownAttribute': UnknownAttribute,
                 'ReflectedFrom': ReflectedFrom,
                 'XorOnly': XorOnly,
                 'XorMappedAddress': XorMappedAddress,
                 'ServerName': ServerName,
                 'SecondaryAddress': SecondaryAddress}

dictMsgTypeToVal = {
    'BindRequestMsg': BindRequestMsg,
    'BindResponseMsg': BindResponseMsg,
    'BindErrorResponseMsg': BindErrorResponseMsg,
    'SharedSecretRequestMsg': SharedSecretRequestMsg,
    'SharedSecretResponseMsg': SharedSecretResponseMsg,
    'SharedSecretErrorResponseMsg': SharedSecretErrorResponseMsg}

dictValToMsgType = {}

dictValToAttr = {}

Blocked = "Blocked"
OpenInternet = "Open Internet"
FullCone = "Full Cone"
SymmetricUDPFirewall = "Symmetric UDP Firewall"
RestricNAT = "Restric NAT"
RestricPortNAT = "Restric Port NAT"
SymmetricNAT = "Symmetric NAT"
ChangedAddressError = "Meet an error, when do Test1 on Changed IP and Port"

def _initialize():
    items = dictAttrToVal.items()
    for i in range(len(items)):
        dictValToAttr.update({items[i][1]: items[i][0]})
    items = dictMsgTypeToVal.items()
    for i in range(len(items)):
        dictValToMsgType.update({items[i][1]: items[i][0]})


def gen_tran_id():
    a = ''.join(random.choice('0123456789ABCDEF') for i in range(32))
    # return binascii.a2b_hex(a)
    return a

def stun_test(sock, host, port, send_data="", count=3):
    retVal = {'Resp': False, 'ExternalIP': None, 'ExternalPort': None,
              'SourceIP': None, 'SourcePort': None, 'ChangedIP': None,
              'ChangedPort': None}
    str_len = "%#04d" % (len(send_data) / 2)
    tranid = gen_tran_id()
    str_data = ''.join([BindRequestMsg, str_len, tranid, send_data])
    data = binascii.a2b_hex(str_data)
    recvCorr = False
    soure_ip, source_port = None, None
    while not recvCorr:
        recieved = False
        while not recieved:
            log.debug("sendto: %s", (host, port))
            try:
                sock.sendto(data, (host, port))
                source_ip, source_port = sock.getsockname()
            except socket.gaierror:
                retVal['Resp'] = False
                return soure_ip, source_port, retVal
            try:
                buf, addr = sock.recvfrom(2048)
                log.debug("recvfrom: %s", addr)
                recieved = True
            except Exception, e:
                print e
                recieved = False
                if count > 0:
                    count -= 1
                else:
                    retVal['Resp'] = False
                    return soure_ip, source_port, retVal
        msgtype = binascii.b2a_hex(buf[0:2])
        bind_resp_msg = dictValToMsgType[msgtype] == "BindResponseMsg"
        tranid_match = tranid.upper() == binascii.b2a_hex(buf[4:20]).upper()
        if bind_resp_msg and tranid_match:
            recvCorr = True
            retVal['Resp'] = True
            len_message = int(binascii.b2a_hex(buf[2:4]), 16)
            len_remain = len_message
            base = 20
            while len_remain:
                attr_type = binascii.b2a_hex(buf[base:(base + 2)])
                attr_len = int(binascii.b2a_hex(buf[(base + 2):(base + 4)]), 16)
                if attr_type == MappedAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))
                    ])
                    retVal['ExternalIP'] = ip
                    retVal['ExternalPort'] = port
                if attr_type == SourceAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))
                    ])
                    retVal['SourceIP'] = ip
                    retVal['SourcePort'] = port
                if attr_type == ChangedAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))
                    ])
                    retVal['ChangedIP'] = ip
                    retVal['ChangedPort'] = port
                # if attr_type == ServerName:
                    # serverName = buf[(base+4):(base+4+attr_len)]
                base = base + 4 + attr_len
                len_remain = len_remain - (4 + attr_len)
    # s.close()
    return soure_ip, source_port, retVal


def get_nat_type(s, stun_host=None, stun_port=3478, only_ip=False, count=3):
    _initialize()
    port = stun_port
    log.debug("Do Test1")
    resp = False
    if stun_host:
        source_ip, source_port, ret = stun_test(s, stun_host, port, count=count)
        resp = ret['Resp']
    else:
        for stun_host in STUN_SERVERS:
            log.debug('Trying STUN host: %s', stun_host)
            source_ip, source_port, ret = stun_test(s, stun_host, port, count=count)
            resp = ret['Resp']
            if resp:
                break

    if not resp:
        if only_ip:
            return None

        return Blocked, None

    log.debug("Result: %s", ret)

    exIP = ret['ExternalIP']
    exPort = ret['ExternalPort']
    changedIP = ret['ChangedIP']
    changedPort = ret['ChangedPort']

    if only_ip:
        return ret['ExternalIP']

    if ret['ExternalIP'] == source_ip:
        changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
        source_ip, source_port, ret = stun_test(s, stun_host, port, changeRequest, count=count)
        if ret['Resp']:
            typ = OpenInternet
        else:
            typ = SymmetricUDPFirewall

    else:
        changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
        log.debug("Do Test2")
        source_ip, source_port, ret = stun_test(s, stun_host, port, changeRequest, count=count)
        log.debug("Result: %s", ret)

        if ret['Resp']:
            typ = FullCone
        else:
            log.debug("Do Test1")
            source_ip, source_port, ret = stun_test(s, changedIP, changedPort, count=count)
            log.debug("Result: %s", ret)
            if not ret['Resp']:
                typ = ChangedAddressError
            elif exIP == ret['ExternalIP'] and exPort == ret['ExternalPort']:
                changePortRequest = ''.join([
                    ChangeRequest, '0004',
                    "00000002"
                ])

                log.debug("Do Test3")
                source_ip, source_port, ret = stun_test(s, changedIP, port, changePortRequest, count=count)
                log.debug("Result: %s", ret)

                if ret['Resp']:
                    typ = RestricNAT
                else:
                    typ = RestricPortNAT
            else:
                typ = SymmetricNAT

    return typ, ret


def get_ip_info(stun_host=None, stun_port=3478):

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(2)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        nat_type, nat = get_nat_type(s, stun_host=stun_host, stun_port=stun_port)
        external_ip = None
        external_port = None
        if nat_type != Blocked:
            external_ip = nat['ExternalIP']
            external_port = nat['ExternalPort']
        return (nat_type, external_ip, external_port)

    finally:
        s.close()

def get_ip(stun_host=None, stun_port=3478):

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(2)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        return get_nat_type(
            s, stun_host=stun_host, stun_port=stun_port, only_ip=True, count=1)

    finally:
        s.close()

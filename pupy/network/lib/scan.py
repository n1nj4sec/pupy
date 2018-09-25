# -*- coding: utf-8 -*-

__all__ = ['scan', 'scanthread']

import socket
import select
import errno
import time
import threading
import rpyc
import random

from netaddr import IPNetwork

from . import getLogger
logger = getLogger('scan')

TOP1000 = [
    1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,
    83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,
    179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,
    417,425,427,443,444,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,
    548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,
    705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,
    901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,
    1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,
    1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,
    1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,
    1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,
    1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,
    1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,
    1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,
    1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,
    1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,
    1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,
    1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,
    2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,
    2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,
    2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,
    2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,
    3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,
    3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,
    3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,
    3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,
    4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,
    4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,
    5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,
    5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,
    5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,
    5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,
    6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,
    6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,
    7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,
    7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,
    8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,
    8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,
    9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,
    9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,
    9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,
    10082,10180, 10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,
    12174,12265,12345,13456,13722
]

def create_socket(host, port):
    sock = socket.socket()
    sock.setblocking(0)

    try:
        r = sock.connect_ex((host, int(port)))
    except:
        return None, None

    return sock, r

def scan(hosts, ports, abort=None, timeout=10, portion=32, on_complete=None, on_open_port=None, pass_socket=False):
    connectable=[]
    targets = ((x, y) for x in hosts for y in ports)
    sockets = {}
    while targets or sockets:
        free = portion - len(sockets)
        chunk = []
        while free and targets:
            try:
                chunk.append(next(targets))
                free -= 1
            except StopIteration:
                targets = None
                break

        if abort and abort.is_set():
            break

        for host, port in chunk:
            logger.debug('%s:%d - check', host, port)
            sock, r = create_socket(host, port)
            if sock is None:
                continue

            if r:
                ok = [errno.EAGAIN, errno.EINPROGRESS]
                if hasattr(errno, 'WSAEWOULDBLOCK'):
                    ok.append(errno.WSAEWOULDBLOCK)

                if r in ok:
                    sockets[sock] = (host, port, time.time())
                else:
                    logger.debug('%d - N/A', port)
                    sock.close()
                    continue
            else:
                logger.debug('%s:%d - ok (fast)', host, port)
                if on_open_port:
                    if pass_socket:
                        on_open_port((host, port, sock))
                    else:
                        on_open_port((host, port))

                connectable.append((host, port))
                if not (pass_socket and on_open_port):
                    sock.close()

        if sockets:
            socks = list(sockets.iterkeys())
            _, w, _ = select.select([], socks, [], timeout)

            for sock in w:
                try:
                    errcode = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if errcode == 0:
                        host, port = sockets[sock][:2]
                        logger.debug('%s:%d - ok', host, port)
                        if on_open_port:
                            if pass_socket:
                                on_open_port((host, port, sock))
                            else:
                                on_open_port((host, port))

                        connectable.append(sockets[sock][:2])
                except Exception, e:
                    logger.exception('%s:%d - error - %s', host, port, e)
                    pass

                finally:
                    if not (errcode == 0 and on_open_port and pass_socket):
                        sock.close()

                    del sockets[sock]

            now = time.time()
            for sock in socks:
                if sock in w or sock not in sockets:
                    continue

                if now - sockets[sock][2] > timeout:
                    logger.debug(
                        '%s:%d - N/A (timeout)',
                        sockets[sock][0],
                        sockets[sock][1])
                    sock.close()
                    del sockets[sock]

    if on_complete:
        if not abort or (abort and not abort.is_set()):
            on_complete(connectable)
    else:
        return connectable

def safe_scan(hosts, ports, abort=None, timeout=10, portion=32, on_complete=None, on_open_port=None, pass_socket=False, on_exception=None):
    try:
        return scan(
            hosts, ports, abort, timeout, portion,
            on_complete, on_open_port, pass_socket)
    except Exception, e:
        if on_exception:
            on_exception(e)
        elif on_complete:
            on_complete([])

def scanthread(hosts, ports, on_complete, **kwargs):
    abort = threading.Event()
    kwargs.update({
        'abort': abort,
        'on_complete': rpyc.async(on_complete)
    })
    scanner = threading.Thread(target=safe_scan, args=(hosts, ports), kwargs=kwargs)
    scanner.daemon = True
    scanner.start()

    return abort

def scanthread_parse(hosts, ports, on_complete, **kwargs):
    targets = []

    for target in hosts.split(','):
        if '/' in target:
            for host in IPNetwork(target):
                targets.append(str(host))
        else:
            targets.append(str(target))

    ports = list({
        p for prange in ports.split(',') for p in (
            xrange(
                int(prange.split('-')[0]), int(prange.split('-')[1])+1
            ) if '-' in prange else [int(prange)]
        )
    })

    random.shuffle(ports)

    return scanthread(targets, ports, on_complete, **kwargs)

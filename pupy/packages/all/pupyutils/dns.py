#!/user/bin/env python
import socket

def getIP(domain):
    """
    This method returns the first IP address string 
    that responds as the given domain name
    """
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return False

def getIPx(domain):
    """
    This method returns an array containing
    one or more IP address strings that respond
    as the given domain name
    """
    try:
        return socket.gethostbyname_ex(domain)[2]
    except Exception:
        return False
#
def getHost(ip):
    """
    This method returns the 'True Host' name for a
    given IP address
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return False
#
def getAlias(domain):
    """
    This method returns an array containing
    a list of aliases for the given domain
    """
    try:
        data = socket.gethostbyname_ex(domain)
        alias = repr(data[1])
        return alias
    except Exception:
        return False

def launch_dns_ip_resolver(ip_or_domain):
    functions = { 'IP': {'function': getIP, 'result': ''}, 
                 'IPx': {'function': getIPx, 'result': ''},
                'Host': {'function': getHost, 'result': ''},
                'Alias': {'function': getAlias, 'result': ''}
        }

    for function in functions:
        functions[function]['result'] = functions[function]['function'](ip_or_domain)

    return functions
# -*- coding: utf-8 -*-

# Stolen from dns.resolver

__all__ = ('dnsinfo',)

import sys


def _parse_resolv_conf(path='/etc/resolv.conf'):
    nameservers = []
    domains = []
    searches = []

    with open(path) as fobj:
        for line in fobj:
            if '#' in line:
                line, _ = line.split('#', 1)

            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            parts = tuple(
                part.strip() for part in parts
            )

            option = parts[0]

            if option == 'nameserver':
                nameserver = parts[1]
                if nameserver in nameservers:
                    continue
                nameservers.append(nameserver)

            elif option == 'domain':
                domain = parts[1]
                if domain in domains:
                    continue
                domains.append(domain)

            elif option == 'search':
                for search in parts[1:]:
                    if search in domains:
                        continue
                    elif search in searches:
                        continue

                    searches.append(search)

    searches = [
        suffix for suffix in searches if not suffix in domains
    ]

    domains.extend(searches)

    return nameservers, domains


def _determine_split_char(entry):
    if entry.find(' ') >= 0:
        split_char = ' '
    elif entry.find(',') >= 0:
        split_char = ','
    else:
        # probably a singleton; treat as a space-separated list.
        split_char = ' '
    return split_char


def _config_win32_nameservers(nameservers):
    if isinstance(nameservers, unicode):
        nameservers = nameservers.encode('utf-8')

    split_char = _determine_split_char(nameservers)
    return list(set(
        nameserver.strip() for nameserver in nameservers.split(split_char)
    ))


def _config_win32_search(searches):
    if isinstance(searches, unicode):
        searches = searches.encode('utf-8')

    split_char = _determine_split_char(searches)
    return list(set(
        search.strip() for search in searches.split(split_char)
    ))


def _config_win32_fromkey(_winreg, key):
    domains = []
    searches = []
    servers = []

    try:
        win_servers, rtype = _winreg.QueryValueEx(key, 'NameServer')
    except WindowsError:  # pylint: disable=undefined-variable
        win_servers = None

    if win_servers:
        servers.extend(_config_win32_nameservers(win_servers))

    try:
        win_domain, rtype = _winreg.QueryValueEx(key, 'Domain')
        if win_domain:
            domains.append(win_domain)
    except WindowsError:  # pylint: disable=undefined-variable
        pass

    try:
        win_servers, rtype = _winreg.QueryValueEx(key, 'DhcpNameServer')
    except WindowsError:  # pylint: disable=undefined-variable
        win_servers = None

    if win_servers:
        for server in _config_win32_nameservers(win_servers):
            if server not in servers:
                servers.append(server)

    try:
        win_domain, rtype = _winreg.QueryValueEx(key, 'DhcpDomain')
        if win_domain and win_domain not in domains:
            domains.append(win_domain)
    except WindowsError:  # pylint: disable=undefined-variable
        pass

    try:
        win_search, rtype = _winreg.QueryValueEx(key, 'SearchList')
    except WindowsError:  # pylint: disable=undefined-variable
        win_search = None

    if win_search:
        for search in win_search:
            if search not in domains and search not in searches:
                searches.append(search)

    return servers, domains, searches


def _win32_is_nic_enabled(_winreg, lm, guid, interface_key):
    # Look in the Windows Registry to determine whether the network
    # interface corresponding to the given guid is enabled.
    #
    # (Code contributed by Paul Marks, thanks!)
    #
    try:
        # This hard-coded location seems to be consistent, at least
        # from Windows 2000 through Vista.
        connection_key = _winreg.OpenKey(
            lm,
            r'SYSTEM\CurrentControlSet\Control\Network'
            r'\{4D36E972-E325-11CE-BFC1-08002BE10318}'
            r'\%s\Connection' % guid)

        try:
            # The PnpInstanceID points to a key inside Enum
            (pnp_id, ttype) = _winreg.QueryValueEx(
                connection_key, 'PnpInstanceID')

            if ttype != _winreg.REG_SZ:
                raise ValueError

            device_key = _winreg.OpenKey(
                lm, r'SYSTEM\CurrentControlSet\Enum\%s' % pnp_id)

            try:
                # Get ConfigFlags for this device
                (flags, ttype) = _winreg.QueryValueEx(
                    device_key, 'ConfigFlags')

                if ttype != _winreg.REG_DWORD:
                    raise ValueError

                # Based on experimentation, bit 0x1 indicates that the
                # device is disabled.
                return not flags & 0x1

            finally:
                device_key.Close()
        finally:
            connection_key.Close()
    except (EnvironmentError, ValueError):
        # Pre-vista, enabled interfaces seem to have a non-empty
        # NTEContextList; this was how dnspython detected enabled
        # nics before the code above was contributed.  We've retained
        # the old method since we don't know if the code above works
        # on Windows 95/98/ME.
        try:
            (nte, ttype) = _winreg.QueryValueEx(interface_key,
                                                'NTEContextList')
            return nte is not None
        except WindowsError:  # pylint: disable=undefined-variable
            return False


def _parse_registry():
    """Extract resolver configuration from the Windows registry."""
    _winreg = __import__('_winreg')

    lm = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
    want_scan = False

    servers = []
    domains = []
    searches = []

    try:
        try:
            # XP, 2000
            tcp_params = _winreg.OpenKey(lm,
                                            r'SYSTEM\CurrentControlSet'
                                            r'\Services\Tcpip\Parameters')
            want_scan = True
        except EnvironmentError:
            # ME
            tcp_params = _winreg.OpenKey(lm,
                                            r'SYSTEM\CurrentControlSet'
                                            r'\Services\VxD\MSTCP')
        try:
            c_servers, c_domains, c_searches = _config_win32_fromkey(
                _winreg, tcp_params)

            for server in c_servers:
                if server not in servers:
                    servers.append(server)

            for domain in c_domains:
                if domain not in domains:
                    domains.append(domain)

            searches.extend(c_searches)

        finally:
            tcp_params.Close()

        if want_scan:
            interfaces = _winreg.OpenKey(lm,
                                            r'SYSTEM\CurrentControlSet'
                                            r'\Services\Tcpip\Parameters'
                                            r'\Interfaces')
            try:
                i = 0
                while True:
                    try:
                        guid = _winreg.EnumKey(interfaces, i)
                        i += 1
                        key = _winreg.OpenKey(interfaces, guid)
                        if not _win32_is_nic_enabled(_winreg, lm, guid, key):
                            continue
                        try:
                            c_servers, c_domains, c_searches = _config_win32_fromkey(
                                _winreg, key)

                            for server in c_servers:
                                if server not in servers:
                                    servers.append(server)

                            for domain in c_domains:
                                if domain not in domains:
                                    domains.append(domain)

                            searches.extend(c_searches)
                        finally:
                            key.Close()
                    except EnvironmentError:
                        break
            finally:
                interfaces.Close()
    finally:
        lm.Close()

    searches = [
        search for search in searches
        if search not in searches and search not in domains
    ]

    domains.extend(searches)
    return servers, domains


def dnsinfo():
    if sys.platform == 'win32':
        return _parse_registry()
    else:
        return _parse_resolv_conf()

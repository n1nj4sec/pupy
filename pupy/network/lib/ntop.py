# -*- coding: utf-8 -*-

__all__ = ('ensure_ntop',)


def ensure_ntop():
    import socket

    if not (hasattr(socket, 'inet_ntop') and hasattr(socket, 'inet_pton')):
        import sys

        try:
            if 'win' in sys.platform:
                import win_inet_pton
                assert win_inet_pton
        except (ImportError, AttributeError):
            # Something went wrong
            pass


    if not (hasattr(socket, 'inet_ntop') and hasattr(socket, 'inet_pton')):
        import netaddr

        def inet_pton(family, address):
            if family == socket.AF_INET:
                return netaddr.strategy.ipv4.int_to_packed(
                    netaddr.strategy.ipv4.str_to_int(address))
            elif family == socket.AF_INET6:
                return netaddr.strategy.ipv6.int_to_packed(
                    netaddr.strategy.ipv6.str_to_int(address))
            else:
                raise ValueError('Unsupported family {}'.format(family))

        def inet_ntop(family, address):
            if family == socket.AF_INET:
                return netaddr.strategy.ipv4.int_to_str(
                    netaddr.strategy.ipv4.packed_to_int(address))
            elif family == socket.AF_INET6:
                return netaddr.strategy.ipv6.int_to_str(
                    netaddr.strategy.ipv6.packed_to_int(address))
            else:
                raise ValueError('Unsupported family {}'.format(family))

        setattr(socket, 'inet_pton', inet_pton)
        setattr(socket, 'inet_ntop', inet_ntop)

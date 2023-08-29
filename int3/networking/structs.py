import ctypes
import ipaddress

from int3.architectures import Endian
from int3.errors import Int3MissingEntityError

# Reference:
# https://git.musl-libc.org/cgit/musl/tree/include/netinet/in.h


# struct sockaddr_in
# {
#     sa_family_t sin_family;
#     in_port_t sin_port;
#     struct in_addr sin_addr;
#     uint8_t sin_zero[8];
# };
class sockaddr_in(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_uint16),
        ("sin_addr", ctypes.c_uint32),
        ("sin_zero", ctypes.c_uint8 * 0x8),
    ]


# struct sockaddr_in6
# {
#     sa_family_t     sin6_family;
#     in_port_t       sin6_port;
#     uint32_t        sin6_flowinfo;
#     struct in6_addr sin6_addr;
#     uint32_t        sin6_scope_id;
# };
class sockaddr_in6(ctypes.Structure):
    _fields_ = [
        ("sin6_family", ctypes.c_ushort),
        ("sin6_port", ctypes.c_uint16),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_uint8 * 0x10),
        ("sin6_scope_id", ctypes.c_uint32),
    ]


def make_sockaddr_in(
    ip_addr: str, port: int, endian: Endian
) -> sockaddr_in6 | sockaddr_in:
    parsed_ip_addr = ipaddress.ip_address(ip_addr)

    if not isinstance(parsed_ip_addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        raise Int3MissingEntityError(
            "Expected Ipv4Address or IPv6Address but got "
            f"{parsed_ip_addr.__class__.__name__}"
        )

    is_ipv4 = isinstance(parsed_ip_addr, ipaddress.IPv4Address)

    endian_mixin_cls = (
        ctypes.BigEndianStructure
        if endian == Endian.Big
        else ctypes.LittleEndianStructure
    )

    if is_ipv4:

        class sockaddr_in_endian_aware(sockaddr_in, endian_mixin_cls):
            pass

        return sockaddr_in_endian_aware(
            # TODO
        )
    else:
        # ipv6
        class sockaddr_in6_endian_aware(sockaddr_in, endian_mixin_cls):
            pass

        return sockaddr_in6_endian_aware(
            # TODO
        )

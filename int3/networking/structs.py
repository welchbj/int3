import ctypes
import ipaddress
import socket
from typing import Type

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

    if is_ipv4:
        sockaddr_in_endian_aware: Type[sockaddr_in]

        if endian == Endian.Big:

            class sockaddr_in_big_endian(sockaddr_in, ctypes.BigEndianStructure):
                pass

            sockaddr_in_endian_aware = sockaddr_in_big_endian
        else:

            class sockaddr_in_little_endian(sockaddr_in, ctypes.LittleEndianStructure):
                pass

            sockaddr_in_endian_aware = sockaddr_in_little_endian

        return sockaddr_in_endian_aware(
            sin_family=socket.AF_INET,
            sin_port=socket.htons(port),
            sin_addr=socket.inet_pton(socket.AF_INET, ip_addr),
            sin_zero=b"\x00" * 0x8,
        )
    else:
        # ipv6

        sockaddr_in6_endian_aware: Type[sockaddr_in6]

        if endian == Endian.Big:

            class sockaddr_in6_big_endian(sockaddr_in6, ctypes.BigEndianStructure):
                pass

            sockaddr_in6_endian_aware = sockaddr_in6_big_endian
        else:

            class sockaddr_in6_little_endian(sockaddr_in6, ctypes.LittleEndianStructure):
                pass

            sockaddr_in6_endian_aware = sockaddr_in6_little_endian

        return sockaddr_in6_endian_aware(
            sin6_family=socket.AF_INET6,
            sin6_port=socket.htons(port),
            sin6_flowinfo=0,
            sin6_addr=socket.inet_pton(socket.AF_INET6, ip_addr),
            sin6_scope_id=0,
        )

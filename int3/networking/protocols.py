from enum import Enum, auto


class NetworkProtocols(Enum):
    Ipv4 = auto()
    Ipv6 = auto()


class TransportProtocols(Enum):
    Udp = auto()
    Tcp = auto()

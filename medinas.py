# coding=utf-8
import struct
from collections import namedtuple
from enum import Enum
from typing import List


class Resolver(object):
    """Resolves DNS queries from name servers"""

    name_servers = []

    def __init__(self, name_servers: List[str]):
        self.name_servers = name_servers

    def a(self, domain_name: str) -> str:
        """Fetches the A record for the given domain_name"""
        pass

    def cname(self, domain_name: str) -> str:
        """Fetches the CNAME record for the given domain_name"""
        pass

    def mx(self, domain_name: str) -> str:
        """Fetches the MX record for the given domain_name"""
        pass

    def ptr(self, domain_name: str) -> str:
        """Fetches the PTR record for the given domain_name"""
        pass

    def soa(self, domain_name: str) -> str:
        """Fetches the SOA record for the given domain_name"""
        pass

    def txt(self, domain_name: str) -> str:
        """Fetches the TXT record for the given domain_name"""
        pass


class Message(object):
    """Represents a DNS message"""

    def __init__(self):
        pass

    def __bytes__(self):
        pass

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS message from binary to a Message object"""
        pass


class HeaderFlags(object):
    """Represents flags in a DNS message header"""

    def __init__(self):
        pass

    def __bytes__(self):
        pass

    @classmethod
    def from_wire(cls, wire):
        """Convert DNS header flags from binary to a HeaderFlags object"""
        pass


RecordsCount = namedtuple('RecordsCount', 'qd, an, ns, ar')


class Question(object):
    """Represents a DNS question section"""

    def __init__(self):
        pass

    def __bytes__(self):
        pass

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS question section from binary to a Question object"""
        pass


class Type(Enum):
    """Enumeration of DNS types"""
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AXFR = 252
    ANY = 255


class Class(Enum):
    """Enumeration of DNS classes"""
    IN = 1
    CH = 2
    HS = 4
    ANY = 255


class ResourceRecord(object):
    """Represents a DNS resource record"""

    def __init__(self):
        pass

    def __bytes__(self):
        pass

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS resource record from binary to a ResourceRecord object"""
        pass


class A(ResourceRecord):
    """Represents a DNS A record"""

    def __init__(self):
        super().__init__()

    def __bytes__(self):
        pass

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS A record from binary to an A object"""
        pass


class CNAME(ResourceRecord):
    """Represents a DNS CNAME record"""

    def __init__(self):
        super().__init__()

    def __bytes__(self):
        pass

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS CNAME record from binary to an CNAME object"""
        pass


class SOA(ResourceRecord):
    """Represents a DNS SOA record"""

    def __init__(self):
        super().__init__()

    def __bytes__(self):
        pass

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS SOA record from binary to an SOA object"""
        pass


class PTR(ResourceRecord):
    """Represents a DNS PTR record"""

    def __init__(self):
        super().__init__()

    def __bytes__(self):
        pass

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS PTR record from binary to a PTR object"""
        pass


class MX(ResourceRecord):
    """Represents a DNS MX record"""

    def __init__(self):
        super().__init__()

    def __bytes__(self):
        pass

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS MX record from binary to a MX object"""
        pass


class TXT(ResourceRecord):
    """Represents a DNS TXT record"""

    def __init__(self):
        super().__init__()

    def __bytes__(self):
        pass

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS TXT record from binary to a TXT object"""
        pass


class Name(object):
    """Stores a string and coverts it into DNS label wire format"""
    domain_name = ''

    def __init__(self, domain_name: str):
        self.domain_name = domain_name

    def __bytes__(self):
        if not self.domain_name.endswith('.'):
            self.domain_name = '{}.'.format(self.domain_name)

        labels = self.domain_name.split('.')

        wire = b''
        for label in labels:
            _ = label.encode()
            stub = struct.pack('>B', len(_)) + _
            wire += stub

        return wire

    def __str__(self):
        return self.domain_name

    def __eq__(self, other):
        return self.__bytes__() == bytes(other)

    @classmethod
    def from_wire(cls, wire: bytes):
        """Encodes DNS labels wire format into a Name class"""
        labels = []

        while wire[0] != 0:
            _len = int(wire[0])
            if _len > 63:
                raise DNSDecodeError()

            label = wire[1:_len + 1]
            wire = wire[_len + 1:]

            labels.append(label.decode(encoding='utf-8'))

        domain_name = '.'.join(labels)

        return cls(domain_name)


class DNSDecodeError(ValueError):
    """Raised when errors are encountered during the decoding of the DNS wire format"""
    pass

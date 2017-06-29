# coding=utf-8
import struct
from collections import namedtuple
from enum import IntEnum
from typing import List


def bitset(content: bytes, value: int, position: int = 0) -> bytes:
    """Set the bits of content at the given position with value"""
    length = len(content)
    content = int.from_bytes(content, 'big')

    mask = 0
    mask |= value
    mask <<= position

    content |= mask
    return content.to_bytes(length, 'big')


def bitget(content: bytearray, position: int = 0, num_bits: int = 1) -> int:
    """Get the num_bits bits of the content from position"""
    content = int.from_bytes(content, 'big')

    content >>= position
    # print(content, pow(2, num_bits), content % pow(2, num_bits)
    return content % pow(2, num_bits)


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
    """
    Represents flags in a DNS message header.

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """

    def __init__(self, response=False, opcode=0, authoritative=False, truncated=False, recursion_desired=False,
                 recursion_available=False, reply_code=0):
        self.response = response
        self.opcode = opcode
        self.authoritative = authoritative
        self.truncated = truncated
        self.recursion_desired = recursion_desired
        self.recursion_available = recursion_available
        self.reply_code = reply_code

    def __bytes__(self):
        wire = b'\x00\x00'

        wire = bitset(wire, self.response, 15)
        wire = bitset(wire, self.opcode, 14)
        wire = bitset(wire, self.authoritative, 10)
        wire = bitset(wire, self.truncated, 9)
        wire = bitset(wire, self.recursion_desired, 8)
        wire = bitset(wire, self.recursion_available, 7)
        wire = bitset(wire, self.reply_code)

        return wire

    @classmethod
    def from_wire(cls, wire):
        """Convert DNS header flags from binary to a HeaderFlags object"""
        response = bitget(wire, 15)
        opcode = bitget(wire, 11, 3)
        authoritative = bitget(wire, 10)
        truncated = bitget(wire, 9)
        recursion_desired = bitget(wire, 8)
        recursion_available = bitget(wire, 7)
        reply_code = bitget(wire, num_bits=4)

        return cls(response, opcode, authoritative, truncated, recursion_desired, recursion_available, reply_code)


RecordsCount = namedtuple('RecordsCount', 'qd, an, ns, ar')


class Question(object):
    """
    Represents a DNS question section

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //                    QNAME                    //
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """

    def __init__(self, name: str, qtype: 'Type', qclass: 'Class'):
        self.name = Name(name)
        self.qtype = qtype
        self.qclass = qclass

    # noinspection PyTypeChecker
    def __bytes__(self):
        wire = b''

        wire += bytes(self.name)
        wire += struct.pack('>H', self.qtype)
        wire += struct.pack('>H', self.qclass)
        return wire

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS question section from binary to a Question object"""
        name, rest = Name.split_by_name(wire)
        name = Name.from_wire(name)
        (qtype, qclass) = struct.unpack('>HH', rest)

        return cls(name, qtype, qclass)


class Type(IntEnum):
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


class Class(IntEnum):
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
        return str(self.domain_name)

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

    @staticmethod
    def split_by_name(wire: bytes):
        """Encodes DNS labels wire format into a Name class"""
        labels = b''

        while wire[0] != 0:
            _len = int(wire[0])
            if _len > 63:
                raise DNSDecodeError()

            labels += wire[:_len + 1]
            wire = wire[_len + 1:]

        labels += wire[:1]
        wire = wire[1:]

        return labels, wire


class DNSDecodeError(ValueError):
    """Raised when errors are encountered during the decoding of the DNS wire format"""
    pass

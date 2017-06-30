# coding=utf-8
import secrets
import struct
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
    """
    Represents a DNS message

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
    """

    def __init__(self, question: 'Question', header=None):
        self.header = MessageHeader() if header is None else header

        if isinstance(question, tuple):
            self.question = Question(*question)
        elif isinstance(question, Question):
            self.question = question

        self.answers = []
        self.authorities = []
        self.additional = []

    # noinspection PyTypeChecker
    def __bytes__(self) -> bytes:
        wire = bytes(self.header)
        wire += bytes(self.question)

        for answer in self.answers:
            wire += bytes(answer)

        for authority in self.authorities:
            wire += bytes(authority)

        for _additional in self.additional:
            wire += bytes(_additional)

        return wire

    @classmethod
    def from_wire(cls, wire):
        """Encodes a DNS message from binary to a Message object"""
        header, wire = MessageHeader.extract_from_wire(wire)

        question, wire = Question.extract_from_wire(wire)

        return cls(question, header)


class MessageHeader(object):
    """Represents a DNS message header"""

    def __init__(self, id=None, flags=None, count=None):
        self.id = int.from_bytes(secrets.token_bytes(2), 'big') if id is None else id
        self.flags = HeaderFlags() if flags is None else flags
        self.count = RecordsCount() if count is None else count

    def __bytes__(self):
        wire = struct.pack('>H', self.id)
        wire += bytes(self.flags)
        wire += bytes(self.count)

        return wire

    @classmethod
    def extract_from_wire(cls, wire):
        """Extracts message header from wire dump"""
        id, wire = wire[:2], wire[2:]
        id = struct.unpack('>H', id)
        flags, wire = HeaderFlags.extract_from_wire(wire)
        count, wire = RecordsCount.extract_from_wire(wire)
        return cls(id, flags, count), wire


class HeaderFlags(object):
    """
    Represents flags in a DNS message header.

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """

    def __init__(self, qr: bool = False, opcode: int = 0, aa: bool = False, tc: bool = False, rd: bool = True,
                 ra: bool = False, rcode: int = 0):
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.rcode = rcode

    def __bytes__(self) -> bytes:
        wire = b'\x00\x00'

        wire = bitset(wire, self.qr, 15)
        wire = bitset(wire, self.opcode, 14)
        wire = bitset(wire, self.aa, 10)
        wire = bitset(wire, self.tc, 9)
        wire = bitset(wire, self.rd, 8)
        wire = bitset(wire, self.ra, 7)
        wire = bitset(wire, self.rcode)

        return wire

    @classmethod
    def extract_from_wire(cls, wire):
        """Convert DNS header flags from binary to a HeaderFlags object"""
        flags = wire[:2]
        wire = wire[2:]
        qr = bitget(flags, 15)
        opcode = bitget(flags, 11, 3)
        aa = bitget(flags, 10)
        tc = bitget(flags, 9)
        rd = bitget(flags, 8)
        ra = bitget(flags, 7)
        rcode = bitget(flags, num_bits=4)

        return cls(qr, opcode, aa, tc, rd, ra, rcode), wire


class RecordsCount(object):
    """Stores counts of records in message"""

    def __init__(self, an: int = 0, ns: int = 0, ar: int = 0):
        self.qd, self.an, self.ns, self.ar = 1, an, ns, ar

    def __bytes__(self):
        return struct.pack('>HHHH', self.qd, self.an, self.ns, self.ar)

    @classmethod
    def extract_from_wire(cls, wire):
        """Extract count of records in message header from wire dump"""
        counts = wire[:8]
        wire = wire[8:]

        qd, an, ns, ar = struct.unpack('>HHHH', counts)
        return cls(an, ns, ar), wire


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

    def __init__(self, name: str, qtype=None, qclass=None):
        qtype = Type.A if qtype is None else qtype
        qclass = Class.IN if qclass is None else qclass
        self.name = Name(name)
        self.qtype = qtype
        self.qclass = qclass

    # noinspection PyTypeChecker
    def __bytes__(self) -> bytes:
        wire = b''

        wire += bytes(self.name)
        wire += struct.pack('>H', self.qtype)
        wire += struct.pack('>H', self.qclass)
        return wire

    @classmethod
    def extract_from_wire(cls, wire):
        """Extract a question section from the wire dump"""
        name, wire = Name.extract_from_wire(wire)
        (qtype, qclass) = struct.unpack('>HH', wire[:4])
        wire = wire[4:]

        return cls(name, qtype, qclass), wire


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

    def __bytes__(self) -> bytes:
        if not self.domain_name.endswith('.'):
            self.domain_name = '{}.'.format(self.domain_name)

        labels = self.domain_name.split('.')

        wire = b''
        for label in labels:
            _ = label.encode()
            stub = struct.pack('>B', len(_)) + _
            wire += stub

        return wire

    def __str__(self) -> str:
        return str(self.domain_name)

    def __eq__(self, other) -> bool:
        return self.__bytes__() == bytes(other)

    @classmethod
    def extract_from_wire(cls, wire: bytes):
        """Extracts a name from the start of a wire dump"""
        labels = []

        while True:
            offset = int(wire[0]) + 1
            if offset > 64 or offset == 0:
                raise DNSDecodeError()

            label = wire[1:offset]
            wire = wire[offset:]

            if offset != 1:
                labels.append(label.decode(encoding='utf-8'))
            else:
                break

        domain_name = '.'.join(labels)

        return cls(domain_name), wire


class DNSDecodeError(ValueError):
    """Raised when errors are encountered during the decoding of the DNS wire format"""
    pass

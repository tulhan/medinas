# coding=utf-8
import struct
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
        """Converts DNS labels wire format into a Name class"""
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

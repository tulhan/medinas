# coding=utf-8

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

    def __init__(self, domain_name: str):
        pass

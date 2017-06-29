# coding=utf-8
import unittest
from unittest import TestCase

from medinas import Name


@unittest.skip('Not Implemented')
class TestResolver(unittest.TestCase):
    def test_a(self):
        self.fail()

    def test_cname(self):
        self.fail()

    def test_mx(self):
        self.fail()

    def test_ptr(self):
        self.fail()

    def test_soa(self):
        self.fail()

    def test_txt(self):
        self.fail()


class TestName(TestCase):
    def test_name(self):
        _ = Name('www.google.com')
        self.assertEqual(_.__bytes__(), b'\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00')

        _ = Name('gen.lib.rus.ec')
        self.assertEqual(_.__bytes__(), b'\x03\x67\x65\x6e\x03\x6c\x69\x62\x03\x72\x75\x73\x02\x65\x63\x00')

        _ = Name('www.microsoft.com.')
        self.assertEqual(_.__bytes__(), b'\x03\x77\x77\x77\x09\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00')

        _ = Name.from_wire(b'\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00')
        self.assertEqual(str(_), 'www.google.com')

        _ = Name.from_wire(b'\x03\x67\x65\x6e\x03\x6c\x69\x62\x03\x72\x75\x73\x02\x65\x63\x00')
        self.assertEqual(str(_), 'gen.lib.rus.ec')

        _ = Name.from_wire(b'\x03\x77\x77\x77\x09\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00')
        self.assertEqual(str(_), 'www.microsoft.com')

        self.assertEqual(Name('www.google.com'), Name('www.google.com.'))


class TestMessage(TestCase):
    pass


class TestHeaderFlags(TestCase):
    pass


class TestQuestion(TestCase):
    pass


class TestResourceRecord(TestCase):
    pass


class TestA(TestCase):
    pass


class TestCNAME(TestCase):
    pass


class TestSOA(TestCase):
    pass


class TestPTR(TestCase):
    pass


class TestMX(TestCase):
    pass


class TestTXT(TestCase):
    pass


if __name__ == '__main__':
    unittest.main()

# coding=utf-8
import unittest
from unittest import TestCase

import medinas


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
        _ = medinas.Name('www.google.com')
        self.assertEqual(_.__bytes__(), b'\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00')

        _ = medinas.Name('gen.lib.rus.ec')
        self.assertEqual(_.__bytes__(), b'\x03\x67\x65\x6e\x03\x6c\x69\x62\x03\x72\x75\x73\x02\x65\x63\x00')

        _ = medinas.Name('www.microsoft.com.')
        self.assertEqual(_.__bytes__(), b'\x03\x77\x77\x77\x09\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00')

        _ = medinas.Name.from_wire(b'\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00')
        self.assertEqual(str(_), 'www.google.com')

        _ = medinas.Name.from_wire(b'\x03\x67\x65\x6e\x03\x6c\x69\x62\x03\x72\x75\x73\x02\x65\x63\x00')
        self.assertEqual(str(_), 'gen.lib.rus.ec')

        _ = medinas.Name.from_wire(b'\x03\x77\x77\x77\x09\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00')
        self.assertEqual(str(_), 'www.microsoft.com')

        self.assertEqual(medinas.Name('www.google.com'), medinas.Name('www.google.com.'))


# noinspection PyTypeChecker
class TestMessage(TestCase):
    def test_message(self):
        message_on_the_wire = b'\xb4\xf2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x09\x6d\x69\x63\x72' \
                              b'\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'

        _ = medinas.Message()
        _.add_question('www.microsoft.com', medinas.Type.A)
        self.assertEqual(bytes(_)[2:], message_on_the_wire[2:])


class TestHeaderFlags(TestCase):
    def test_header_flags(self):
        _ = medinas.HeaderFlags(recursion_desired=True)
        self.assertEqual(_.__bytes__(), b'\x01\x00')

        _ = medinas.HeaderFlags(response=True, authoritative=True, recursion_desired=True, recursion_available=True,
                                reply_code=3)
        self.assertEqual(_.__bytes__(), b'\x85\x83')

        _ = medinas.HeaderFlags.from_wire(b'\x01\x00')
        self.assertEqual(_.response, False)
        self.assertEqual(_.opcode, 0)
        self.assertEqual(_.authoritative, False)
        self.assertEqual(_.truncated, False)
        self.assertEqual(_.recursion_desired, True)
        self.assertEqual(_.recursion_available, False)
        self.assertEqual(_.reply_code, 0)

        _ = medinas.HeaderFlags.from_wire(b'\x85\x83')
        self.assertEqual(_.response, True)
        self.assertEqual(_.opcode, 0)
        self.assertEqual(_.authoritative, True)
        self.assertEqual(_.truncated, False)
        self.assertEqual(_.recursion_desired, True)
        self.assertEqual(_.recursion_available, True)
        self.assertEqual(_.reply_code, 3)


class TestQuestion(TestCase):
    def test_question(self):
        _ = medinas.Question('www.microsoft.com', medinas.Type.A, medinas.Class.IN).__bytes__()
        self.assertEqual(_,
                         b'\x03\x77\x77\x77\x09\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00\x00\x01\x00\x01')

        _ = medinas.Question.from_wire(
            b'\x03\x77\x77\x77\x09\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00\x00\x01\x00\x01')

        self.assertEqual(str(_.name), 'www.microsoft.com')
        self.assertEqual(_.qtype, medinas.Type.A)
        self.assertEqual(_.qclass, medinas.Class.IN)


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

# coding=utf-8
import struct
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

        _, rest = medinas.Name.extract_from_wire(
            b'\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x01\x02')
        self.assertEqual(str(_), 'www.google.com')
        self.assertEqual(rest, b'\x01\x02')

        _, rest = medinas.Name.extract_from_wire(b'\x03\x67\x65\x6e\x03\x6c\x69\x62\x03\x72\x75\x73\x02\x65\x63\x00')
        self.assertEqual(str(_), 'gen.lib.rus.ec')

        _, rest = medinas.Name.extract_from_wire(
            b'\x03\x77\x77\x77\x09\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00')
        self.assertEqual(str(_), 'www.microsoft.com')

        self.assertEqual(medinas.Name('www.google.com'), medinas.Name('www.google.com.'))


# noinspection PyTypeChecker
class TestMessage(TestCase):
    def test_message(self):
        message_on_the_wire = b'\xb4\xf2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x09\x6d\x69\x63\x72' \
                              b'\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'

        _ = medinas.Message(('www.microsoft.com', medinas.Type.A))
        self.assertEqual(bytes(_)[2:], message_on_the_wire[2:])

        _ = medinas.Message.from_wire(message_on_the_wire)
        self.assertEqual(_.header.id, struct.unpack('>H', b'\xb4\xf2'))
        self.assertEqual(_.header.count.qd, 1)
        self.assertEqual(str(_.question.name), 'www.microsoft.com')


# noinspection PyTypeChecker
class TestMessageHeader(TestCase):
    def test_message_header(self):
        x = b'\xc2\xf5\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
        flags = medinas.HeaderFlags()
        count = medinas.RecordsCount(ar=1)
        _ = medinas.MessageHeader(flags=flags, count=count)
        self.assertEqual(bytes(_)[2:], x[2:])


class TestHeaderFlags(TestCase):
    def test_header_flags(self):
        _ = medinas.HeaderFlags(rd=True)
        self.assertEqual(_.__bytes__(), b'\x01\x00')

        _ = medinas.HeaderFlags(qr=True, aa=True, rd=True, ra=True, rcode=3)
        self.assertEqual(_.__bytes__(), b'\x85\x83')

        _, rest = medinas.HeaderFlags.extract_from_wire(b'\x01\x00')
        self.assertEqual(_.qr, False)
        self.assertEqual(_.opcode, 0)
        self.assertEqual(_.aa, False)
        self.assertEqual(_.tc, False)
        self.assertEqual(_.rd, True)
        self.assertEqual(_.ra, False)
        self.assertEqual(_.rcode, 0)

        _, rest = medinas.HeaderFlags.extract_from_wire(b'\x85\x83')
        self.assertEqual(_.qr, True)
        self.assertEqual(_.opcode, 0)
        self.assertEqual(_.aa, True)
        self.assertEqual(_.tc, False)
        self.assertEqual(_.rd, True)
        self.assertEqual(_.ra, True)
        self.assertEqual(_.rcode, 3)


class TestRecordsCount(TestCase):
    def test_records_count(self):
        x = b'\x00\x01\x00\x02\x00\x03\x00\x04'
        _ = medinas.RecordsCount(2, 3, 4)
        self.assertEqual(bytes(_), x)

        _, rest = medinas.RecordsCount.extract_from_wire(x)
        self.assertEqual(_.qd, 1)
        self.assertEqual(_.an, 2)
        self.assertEqual(_.ns, 3)
        self.assertEqual(_.ar, 4)


class TestQuestion(TestCase):
    def test_question(self):
        _ = medinas.Question('www.microsoft.com', medinas.Type.A, medinas.Class.IN).__bytes__()
        self.assertEqual(_,
                         b'\x03\x77\x77\x77\x09\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00\x00\x01\x00\x01')

        _, rest = medinas.Question.extract_from_wire(
            b'\x03\x77\x77\x77\x09\x6d\x69\x63\x72\x6f\x73\x6f\x66\x74\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x01\x02')
        self.assertEqual(str(_.name), 'www.microsoft.com')
        self.assertEqual(_.qtype, medinas.Type.A)
        self.assertEqual(_.qclass, medinas.Class.IN)
        self.assertEqual(rest, b'\x01\x02')


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

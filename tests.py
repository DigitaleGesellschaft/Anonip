#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Unittests for anonip.
"""


import unittest
import anonip
from io import StringIO
import sys
import argparse
import logging

# Keep the output clean
logging.basicConfig(level=logging.ERROR)

DATA = {'first4': '192.168.100.200 some string',
        'second4': 'some 192.168.100.200 string',
        'third4': 'some string 192.168.100.200',
        'multi4': '192.168.100.200 192.168.100.200 192.168.100.200'}

DATA_RESULT = {'first4': '192.168.96.0 some string',
               'second4': 'some 192.168.96.0 string',
               'third4': 'some string 192.168.96.0',
               'multi4': '192.168.96.0 192.168.96.0 192.168.96.0'}


class TestAnonipClass(unittest.TestCase):
    def setUp(self):
        self.anonip = anonip.Anonip()

    def test_process_line_v4(self):
        ip = '192.168.100.200'
        ip_port = '192.168.100.200:80'
        self.assertEqual(self.anonip.process_line(ip), '192.168.96.0')
        self.assertEqual(self.anonip.process_line(ip_port), '192.168.96.0:80')
        self.anonip.ipv4mask = 0
        self.assertEqual(self.anonip.process_line(ip), '192.168.100.200')
        self.anonip.ipv4mask = 4
        self.assertEqual(self.anonip.process_line(ip), '192.168.100.192')
        self.anonip.ipv4mask = 8
        self.assertEqual(self.anonip.process_line(ip), '192.168.100.0')
        self.anonip.ipv4mask = 24
        self.assertEqual(self.anonip.process_line(ip), '192.0.0.0')
        self.anonip.ipv4mask = 32
        self.assertEqual(self.anonip.process_line(ip), '0.0.0.0')
        self.assertEqual(self.anonip.process_line('no_ip_address'),
                         'no_ip_address')

    def test_process_line_v6(self):
        ip = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        self.assertEqual(self.anonip.process_line(ip),
                         '2001:db8:85a0::')
        self.anonip.ipv6mask = 0
        self.assertEqual(self.anonip.process_line(ip),
                         '2001:db8:85a3::8a2e:370:7334')
        self.anonip.ipv6mask = 4
        self.assertEqual(self.anonip.process_line(ip),
                         '2001:db8:85a3::8a2e:370:7330')
        self.anonip.ipv6mask = 8
        self.assertEqual(self.anonip.process_line(ip),
                         '2001:db8:85a3::8a2e:370:7300')
        self.anonip.ipv6mask = 24
        self.assertEqual(self.anonip.process_line(ip),
                         '2001:db8:85a3::8a2e:300:0')
        self.anonip.ipv6mask = 32
        self.assertEqual(self.anonip.process_line(ip),
                         '2001:db8:85a3::8a2e:0:0')
        self.anonip.ipv6mask = 64
        self.assertEqual(self.anonip.process_line(ip),
                         '2001:db8:85a3::')
        self.anonip.ipv6mask = 128
        self.assertEqual(self.anonip.process_line(ip),
                         '::')

    def test_column(self):
        self.assertEqual(self.anonip.process_line(DATA['first4']),
                         DATA_RESULT['first4'])
        self.anonip.columns = [2]
        self.assertEqual(self.anonip.process_line(DATA['second4']),
                         DATA_RESULT['second4'])
        self.anonip.columns = [3]
        self.assertEqual(self.anonip.process_line(DATA['third4']),
                         DATA_RESULT['third4'])
        self.anonip.columns = [1, 2, 3]
        self.assertEqual(self.anonip.process_line(DATA['multi4']),
                         DATA_RESULT['multi4'])

    def test_run(self):
        sys.stdin = StringIO(u'192.168.100.200\n1.2.3.4\n\n')
        lines = []
        for line in self.anonip.run():
            lines.append(line)
        self.assertEqual(lines[0], '192.168.96.0')
        self.assertEqual(lines[1], '1.2.0.0')


class TestAnonipCli(unittest.TestCase):
    def test_parse_arguments(self):
        self.assertEqual(anonip.parse_arguments(['-c', '3', '5']).columns,
                         [3, 5])
        self.assertEqual(anonip.parse_arguments(['-4', '24']).ipv4mask, 24)
        self.assertEqual(anonip.parse_arguments(['-6', '64']).ipv6mask, 64)

    def test_verify_ipv4mask(self):
        for value in ['0', '33', 'string']:
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._verify_ipv4mask, value)

    def test_verify_ipv6mask(self):
        for value in ['0', '129', 'string']:
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._verify_ipv6mask, value)

    def test_verify_integer_ht_1(self):
        for value in ['0', 'string']:
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._verify_integer_ht_1, value)

    def test_verify_increment(self):
        for value in ['0', '2844131328', 'string']:
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._verify_increment, value)


if __name__ == '__main__':
    unittest.main()

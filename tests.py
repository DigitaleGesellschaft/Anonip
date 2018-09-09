#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Unittests for anonip.
"""


import unittest
import anonip
from io import StringIO
import sys
import os
import argparse
import logging


# Keep the output clean
logging.disable(logging.CRITICAL)

DATA = {'first4': '192.168.100.200 some string',
        'second4': 'some 192.168.100.200 string',
        'third4': 'some string 192.168.100.200',
        'multi4': '192.168.100.200 192.168.11.222 192.168.123.234'}

DATA_RESULT = {'first4': '192.168.96.0 some string',
               'second4': 'some 192.168.96.0 string',
               'third4': 'some string 192.168.96.0',
               'multi4': '192.168.96.0 192.168.0.0 192.168.112.0'}


def remove_file(filename):
    try:
        os.remove(filename)
    except OSError:
        pass


class TestAnonipClass(unittest.TestCase):
    def setUp(self):
        self.anonip = anonip.Anonip()

    def test_process_line_v4(self):
        ip = '192.168.100.200'
        self.assertEqual(self.anonip.process_line(ip), '192.168.96.0')
        self.assertEqual(self.anonip.process_line(
            '192.168.100.200:80'),
            '192.168.96.0:80')
        self.assertEqual(self.anonip.process_line(
            '192.168.100.200]'),
            '192.168.96.0]')
        self.assertEqual(self.anonip.process_line(
            '192.168.100.200:80]'),
            '192.168.96.0:80]')
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

        self.assertEqual(self.anonip.process_line(
            '[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443'),
            '[2001:db8:85a0::]:443')

        self.assertEqual(self.anonip.process_line(
            '[2001:0db8:85a3:0000:0000:8a2e:0370:7334]'),
            '[2001:db8:85a0::]')

        self.assertEqual(self.anonip.process_line(
            '[2001:0db8:85a3:0000:0000:8a2e:0370:7334]]'),
            '[2001:db8:85a0::]]')

        self.assertEqual(self.anonip.process_line(
            '[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443]'),
            '[2001:db8:85a0::]:443]')

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

    def test_replace(self):
        self.anonip.replace = 'replacement'
        self.assertEqual(self.anonip.process_line('something something'),
                         'replacement something')

    def test_delimiter(self):
        self.anonip.delimiter = ';'
        self.anonip.columns = [2]
        self.assertEqual(
            self.anonip.process_line(DATA['second4'].replace(' ', ';')),
            DATA_RESULT['second4'].replace(' ', ';'))

    def test_private(self):
        self.anonip.skip_private = True
        self.assertEqual(self.anonip.process_line(
            '192.168.100.200'),
            '192.168.100.200')
        self.assertEqual(self.anonip.process_line(
            'fd9e:21a7:a92c:2323::1'),
            'fd9e:21a7:a92c:2323::1')

    def test_run(self):
        sys.stdin = StringIO(u'192.168.100.200\n1.2.3.4\n\n')
        lines = []
        for line in self.anonip.run():
            lines.append(line)
        self.assertEqual(lines[0], '192.168.96.0')
        self.assertEqual(lines[1], '1.2.0.0')


class TestAnonipCli(unittest.TestCase):
    def test_columns_arg(self):
        self.assertEqual(anonip.parse_arguments(['-c', '3', '5']).columns,
                         [3, 5])

    def test_ipv4mask_arg(self):
        self.assertEqual(anonip.parse_arguments(['-4', '24']).ipv4mask, 24)

    def test_ipv6mask_arg(self):
        self.assertEqual(anonip.parse_arguments(['-6', '64']).ipv6mask, 64)

    def test_umask_arg(self):
        self.assertEqual(anonip.parse_arguments(['-m', '044']).umask, 36)

    def test_set_umask(self):
        self.assertFalse(anonip.set_umask('no umask'))
        self.assertTrue(anonip.set_umask(36))
        self.assertEqual(os.umask(0), 36)

    def test_validate_ipv4mask(self):
        self.assertEqual(anonip._validate_ipv4mask('1'), 1)
        for value in ['0', '33', 'string']:
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._validate_ipv4mask, value)

    def test_validate_ipv6mask(self):
        self.assertEqual(anonip._validate_ipv6mask('1'), 1)
        for value in ['0', '129', 'string']:
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._validate_ipv6mask, value)

    def test_validate_umask(self):
        self.assertEqual(anonip._validate_umask('022'), 18)
        self.assertRaises(argparse.ArgumentTypeError,
                          anonip._validate_umask, '028')

    def test_validate_integer_ht_0(self):
        for value in ['0', 'string']:
            self.assertEqual(anonip._validate_integer_ht_0('1'), 1)
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._validate_integer_ht_0, value)

    def test_validate_increment(self):
        self.assertEqual(anonip._validate_increment('1'), 1)
        for value in ['0', '2844131328', 'string']:
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._validate_increment, value)


class TestMainWithFile(unittest.TestCase):
    def setUp(self):
        self.log_file = '/tmp/anonip.log'
        if os.path.exists(self.log_file):
            raise Exception('File "{}" already exists!'.format(self.log_file))
        self.old_sys_argv = sys.argv
        sys.argv = ['anonip.py',
                    '-o', self.log_file,
                    '-c', '2',
                    '-4', '12',
                    '-6', '42',
                    '-i', '1',
                    '-l', ';',
                    '-r', 'replace',
                    '-p']

    def tearDown(self):
        sys.argv = self.old_sys_argv
        remove_file(self.log_file)

    def test_main_writing_to_file(self):
        sys.stdin = StringIO(
            u'string;192.168.100.200\n'
            u'string;1.2.3.4\n'
            u'string;2001:0db8:85a3:0000:0000:8a2e:0370:7334\n'
            u'string;2a00:1450:400a:803::200e\n'
            u'string;string\n\n')
        anonip.main()
        self.assertTrue(os.path.exists(self.log_file))
        with open(self.log_file, 'r') as f:
            lines = f.readlines()

        self.assertEqual(lines[0], 'string;192.168.100.200\n')
        self.assertEqual(lines[1], 'string;1.2.0.1\n')
        self.assertEqual(lines[2], 'string;2001:db8:85a3::8a2e:370:7334\n')
        self.assertEqual(lines[3], 'string;2a00:1450:400a:803::1\n')
        self.assertEqual(lines[4], 'string;replace\n')


if __name__ == '__main__':
    unittest.main()

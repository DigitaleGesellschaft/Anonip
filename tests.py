#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Unittests for anonip.
"""


from __future__ import unicode_literals, print_function
import unittest
import anonip
from io import StringIO
from contextlib import contextmanager
import sys
import os
import argparse
import logging


# Keep the output clean
logging.disable(logging.CRITICAL)

DATA = {'first4': '192.168.100.200 some string with öéäü',
        'second4': 'some 192.168.100.200 string with öéäü',
        'third4': 'some string 192.168.100.200 with öéäü',
        'multi4': '192.168.100.200 192.168.11.222 192.168.123.234'}

DATA_RESULT = {'first4': '192.168.96.0 some string with öéäü',
               'second4': 'some 192.168.96.0 string with öéäü',
               'third4': 'some string 192.168.96.0 with öéäü',
               'multi4': '192.168.96.0 192.168.0.0 192.168.112.0'}


def remove_file(filename):
    try:
        os.remove(filename)
    except OSError:
        pass


@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


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

    def test_increment(self):
        self.anonip.increment = 3
        self.assertEqual(self.anonip.process_line(
            '192.168.100.200'),
            '192.168.96.3')
        self.anonip.increment = 284414028745874325
        self.assertEqual(self.anonip.process_line(
            '192.168.100.200'),
            '192.168.96.0')

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
        self.anonip.columns = [9999]
        self.assertEqual(self.anonip.process_line(DATA['multi4']),
                         DATA['multi4'])

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

    def test_validate_ipmask(self):
        self.assertEqual(anonip._validate_ipmask('1', 32), 1)
        for value in ['0', '33', 'string']:
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._validate_ipmask, value, 32)

        self.assertEqual(anonip._validate_ipmask('1', 128), 1)
        for value in ['0', '129', 'string']:
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._validate_ipmask, value, 128)

    def test_validate_integer_ht_0(self):
        for value in ['0', 'string']:
            self.assertEqual(anonip._validate_integer_ht_0('1'), 1)
            self.assertRaises(argparse.ArgumentTypeError,
                              anonip._validate_integer_ht_0, value)


class TestMainWithFile(unittest.TestCase):
    def setUp(self):
        self.log_file = '/tmp/anonip.log'
        if os.path.exists(self.log_file):
            raise Exception('File "{}" already exists!'.format(self.log_file))
        self.old_sys_argv = sys.argv
        sys.argv = ['anonip.py',
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

    def test_main_writing_to_file_debug(self):
        sys.argv += ['-o', self.log_file, '-d']
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

        logger = logging.getLogger('anonip')
        self.assertEqual(logger.level, 10)

    def test_main_to_stdout_no_debug(self):
        sys.stdin = StringIO(
            u'string;192.168.100.200\n'
            u'string;1.2.3.4\n'
            u'string;2001:0db8:85a3:0000:0000:8a2e:0370:7334\n'
            u'string;2a00:1450:400a:803::200e\n'
            u'string;string\n\n')
        with captured_output() as (out, err):
            anonip.main()
        lines = out.getvalue().split('\n')

        self.assertEqual(lines[0], 'string;192.168.100.200')
        self.assertEqual(lines[1], 'string;1.2.0.1')
        self.assertEqual(lines[2], 'string;2001:db8:85a3::8a2e:370:7334')
        self.assertEqual(lines[3], 'string;2a00:1450:400a:803::1')
        self.assertEqual(lines[4], 'string;replace')

        logger = logging.getLogger('anonip')
        self.assertEqual(logger.level, 30)


if __name__ == '__main__':
    unittest.main()

#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Tests for anonip.
"""


from __future__ import print_function, unicode_literals

import argparse
import logging
import sys
from io import StringIO

import pytest

import anonip

# Keep the output clean
logging.disable(logging.CRITICAL)


@pytest.mark.parametrize(
    "ip,v4mask,v6mask,expected",
    [
        ("192.168.100.200", 12, 84, "192.168.96.0"),
        ("192.168.100.200:80", 12, 84, "192.168.96.0:80"),
        ("192.168.100.200]", 12, 84, "192.168.96.0]"),
        ("192.168.100.200:80]", 12, 84, "192.168.96.0:80]"),
        ("192.168.100.200", 0, 84, "192.168.100.200"),
        ("192.168.100.200", 4, 84, "192.168.100.192"),
        ("192.168.100.200", 8, 84, "192.168.100.0"),
        ("192.168.100.200", 24, 84, "192.0.0.0"),
        ("192.168.100.200", 32, 84, "0.0.0.0"),
        ("no_ip_address", 12, 84, "no_ip_address"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 12, 84, "2001:db8:85a0::"),
        (
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443",
            12,
            84,
            "[2001:db8:85a0::]:443",
        ),
        ("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]", 12, 84, "[2001:db8:85a0::]"),
        ("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]]", 12, 84, "[2001:db8:85a0::]]"),
        (
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443]",
            12,
            84,
            "[2001:db8:85a0::]:443]",
        ),
        (
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            12,
            0,
            "2001:db8:85a3::8a2e:370:7334",
        ),
        (
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            12,
            4,
            "2001:db8:85a3::8a2e:370:7330",
        ),
        (
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            12,
            8,
            "2001:db8:85a3::8a2e:370:7300",
        ),
        (
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            12,
            24,
            "2001:db8:85a3::8a2e:300:0",
        ),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 12, 32, "2001:db8:85a3::8a2e:0:0"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 12, 62, "2001:db8:85a3::"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 12, 128, "::"),
        ("   foo", 12, 84, "   foo"),
    ],
)
def test_process_line(ip, v4mask, v6mask, expected):
    a = anonip.Anonip(ipv4mask=v4mask, ipv6mask=v6mask)
    assert a.process_line(ip) == expected


@pytest.mark.parametrize(
    "ip,increment,expected",
    [
        ("192.168.100.200", 3, "192.168.96.3"),
        ("192.168.100.200", 284414028745874325, "192.168.96.0"),
    ],
)
def test_increment(ip, increment, expected):
    a = anonip.Anonip(increment=increment)
    assert a.process_line(ip) == expected


@pytest.mark.parametrize(
    "line,columns,expected",
    [
        (
            "192.168.100.200 some string with öéäü",
            None,
            "192.168.96.0 some string with öéäü",
        ),
        (
            "some 192.168.100.200 string with öéäü",
            [2],
            "some 192.168.96.0 string with öéäü",
        ),
        (
            "some string 192.168.100.200 with öéäü",
            [3],
            "some string 192.168.96.0 with öéäü",
        ),
        (
            "192.168.100.200 192.168.11.222 192.168.123.234",
            [1, 2, 3],
            "192.168.96.0 192.168.0.0 192.168.112.0",
        ),
        (
            "192.168.100.200 192.168.11.222 192.168.123.234",
            [9999],
            "192.168.100.200 192.168.11.222 192.168.123.234",
        ),
    ],
)
def test_column(line, columns, expected):
    a = anonip.Anonip(columns=columns)
    assert a.process_line(line) == expected


def test_replace():
    a = anonip.Anonip(replace="replacement")
    assert a.process_line("bla something") == "replacement something"


def test_delimiter():
    a = anonip.Anonip(delimiter=";")
    assert (
        a.process_line("192.168.100.200;some;string;with;öéäü")
        == "192.168.96.0;some;string;with;öéäü"
    )


def test_private():
    a = anonip.Anonip(skip_private=True)
    assert a.process_line("192.168.100.200") == "192.168.100.200"


def test_run(monkeypatch):
    a = anonip.Anonip()

    monkeypatch.setattr(
        "sys.stdin", StringIO("192.168.100.200\n1.2.3.4\n  \n9.8.130.6\n")
    )

    lines = [line for line in a.run()]
    assert lines == ["192.168.96.0", "1.2.0.0", "", "9.8.128.0"]


def test_run_with_input_file():
    a = anonip.Anonip()

    input_file = StringIO("192.168.100.200\n1.2.3.4\n  \n9.8.130.6\n")

    lines = [line for line in a.run(input_file)]
    assert lines == ["192.168.96.0", "1.2.0.0", "", "9.8.128.0"]


@pytest.mark.parametrize(
    "args,attribute,expected",
    [
        (["-c", "3", "5"], "columns", [3, 5]),
        (["-4", "24"], "ipv4mask", 24),
        (["-6", "64"], "ipv6mask", 64),
    ],
)
def test_cli_generic_args(args, attribute, expected):
    assert getattr(anonip.parse_arguments(args), attribute) == expected


@pytest.mark.parametrize(
    "value,valid,bits",
    [
        ("1", True, 32),
        ("0", False, 32),
        ("33", False, 32),
        ("string", False, 32),
        ("129", False, 128),
    ],
)
def test_cli_validate_ipmask(value, valid, bits):
    if valid:
        assert anonip._validate_ipmask(value, bits) == int(value)
    else:
        with pytest.raises(argparse.ArgumentTypeError):
            anonip._validate_ipmask(value, bits)


@pytest.mark.parametrize(
    "value,valid", [("1", True), ("0", False), ("-1", False), ("string", False)]
)
def test_cli_validate_integer_ht_0(value, valid):
    if valid:
        assert anonip._validate_integer_ht_0(value) == int(value)
    else:
        with pytest.raises(argparse.ArgumentTypeError):
            anonip._validate_integer_ht_0(value)


@pytest.mark.parametrize("to_file", [False, True])
@pytest.mark.parametrize("debug,log_level", [(False, 30), (True, 10)])
def test_main(
    to_file,
    debug,
    log_level,
    backup_and_restore_sys_argv,
    capsys,
    monkeypatch,
    tmp_path,
):
    log_file = tmp_path / "anonip.log"
    sys.argv = [
        "anonip.py",
        "-c",
        "2",
        "-4",
        "12",
        "-6",
        "42",
        "-i",
        "1",
        "-l",
        ";",
        "-r",
        "replace",
        "-p",
    ]
    if to_file:
        sys.argv += ["-o", str(log_file)]
    if debug:
        sys.argv.append("-d")

    monkeypatch.setattr(
        "sys.stdin",
        StringIO(
            "string;192.168.100.200\n"
            "string;1.2.3.4\n"
            "string;2001:0db8:85a3:0000:0000:8a2e:0370:7334\n"
            "string;2a00:1450:400a:803::200e\n"
            "string;string\n"
        ),
    )
    anonip.main()

    if to_file:
        with log_file.open() as f:
            lines = [line.rstrip("\n") for line in f.readlines()]
    else:
        captured = capsys.readouterr()
        lines = captured.out.split("\n")[:-1]

    assert lines == [
        "string;192.168.100.200",
        "string;1.2.0.1",
        "string;2001:db8:85a3::8a2e:370:7334",
        "string;2a00:1450:400a:803::1",
        "string;replace",
    ]

    logger = logging.getLogger("anonip")
    assert logger.level == log_level


def test_main_reading_from_input_file(tmp_path, capsys, backup_and_restore_sys_argv):
    input_filename = tmp_path / "anonip-input.txt"
    input_filename.write_text(
        "192.168.100.200 string\n"
        "1.2.3.4 string\n"
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334 string\n"
        "2a00:1450:400a:803::200e string\n"
    )
    sys.argv = ["anonip.py", "--input", str(input_filename), "-d"]
    anonip.main()
    captured = capsys.readouterr()
    lines = captured.out.split("\n")[:-1]
    assert lines == [
        "192.168.96.0 string",
        "1.2.0.0 string",
        "2001:db8:85a0:: string",
        "2a00:1450:4000:: string",
    ]


def test_prefixes_dict():
    a = anonip.Anonip(ipv4mask=11, ipv6mask=83)
    prefixes = a._prefixes
    assert len(prefixes) == 2
    assert 4 in prefixes and bool(prefixes[4])
    assert 6 in prefixes and bool(prefixes[6])


def test_properties_v4():
    a = anonip.Anonip(ipv4mask=11, ipv6mask=83)
    assert a.ipv4mask == 11
    assert a._prefixes[4] == 21


def test_properties_v6():
    a = anonip.Anonip(ipv4mask=11, ipv6mask=83)
    assert a.ipv6mask == 83
    assert a._prefixes[6] == 45


def test_properties_columns():
    a = anonip.Anonip()
    assert a.columns == [0]
    a.columns = [5, 6]
    assert a.columns == [4, 5]

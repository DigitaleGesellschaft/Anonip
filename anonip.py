#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
An IP address anonymizer
Digitale Gesellschaft
https://www.digitale-gesellschaft.ch.
Special thanks to: Thomas B. and Fabio R.

Copyright (c) 2013 - 2016, Swiss Privacy Foundation
              2016 - 2018, Digitale Gesellschaft
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
 * Neither the name of Digitale Gesellschaft nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
"""

from __future__ import print_function, unicode_literals

import argparse
import logging
import sys
from io import open

try:
    import ipaddress
except ImportError:  # pragma: no cover
    # Could happen with python < 3.3
    print("\033[31;1mError: Module ipaddress not found.\033[0m", file=sys.stderr)
    sys.exit(1)
try:
    from urllib.parse import urlparse
except ImportError:  # pragma: no cover
    # compatibility for python < 3
    from urlparse import urlparse


__title__ = "anonip"
__description__ = "Anonip is a tool to anonymize IP-addresses in log files."
__version__ = "1.0.0"
__license__ = "BSD"
__author__ = "Digitale Gesellschaft"

logger = logging.getLogger(__name__)
logging.basicConfig()


class Anonip(object):
    def __init__(
        self,
        columns=None,
        ipv4mask=12,
        ipv6mask=84,
        increment=0,
        delimiter=" ",
        replace=None,
        skip_private=False,
    ):
        """
        Main class for anonip.

        :param columns: list of ints
        :param ipv4mask: int
        :param ipv6mask: int
        :param increment: int
        :param delimiter: str
        :param replace: str
        :param skip_private: bool
        """
        self.columns = columns if columns else [1]
        self.ipv4mask = ipv4mask
        self.ipv6mask = ipv6mask
        self.increment = increment
        self.delimiter = delimiter
        self.replace = replace
        self.skip_private = skip_private

    def run(self):
        """
        Generator that reads from stdin and loops forever.

        Yields anonymized log lines.

        :return: None
        """
        while 1:
            try:
                line = sys.stdin.readline()
            except IOError as err:  # pragma: no cover
                # if reading from stdin fails, exit
                logger.warning(err)
                break
            except KeyboardInterrupt:  # pragma: no cover
                break
            else:
                line = line.rstrip()

            # if line couldn't be read (e.g. when EOF has been received)
            # exit the loop
            if not line:
                break

            logger.debug("Got line: {}".format(line))

            yield self.process_line(line)

    def process_ip(self, ip):
        """
        Process a single ip.

        :param ip: /32 ipaddress.IPv4Network or /128 ipaddress.IPv6Network
        :return: ipaddress.IPv4Address or ipaddress.IPv6Address
        """
        if self.skip_private and ip[0].is_private:
            return ip[0]
        else:
            trunc_ip = self.truncate_address(ip)
            if self.increment:
                try:
                    trunc_ip = trunc_ip + self.increment
                except ipaddress.AddressValueError:
                    logger.error(
                        "Could not increment IP {} by {}".format(
                            trunc_ip, self.increment
                        )
                    )
            return trunc_ip

    def process_line(self, line):
        """
        This function processes a single line.

        It returns the anonymized log line as string.

        :param line: str
        :return: str
        """
        loglist = line.split(self.delimiter)

        for index in self.columns:
            decindex = index - 1
            try:
                loglist[decindex]
            except IndexError:
                logger.warning("Column {} does not exist!".format(self.columns))
                continue
            else:
                ip_str, ip = self.extract_ip(loglist[decindex])
                if ip:
                    trunc_ip = self.process_ip(ip)
                    loglist[decindex] = loglist[decindex].replace(ip_str, str(trunc_ip))
                elif self.replace:
                    loglist[decindex] = self.replace

        return self.delimiter.join(loglist)

    @staticmethod
    def extract_ip(column):
        """
        This function extracts the ip from the column and returns it.

        It can handle following ip formats:
         - 192.168.100.200
         - 192.168.100.200:80
         - 192.168.100.200]
         - 192.168.100.200:80]
         - 2001:0db8:85a3:0000:0000:8a2e:0370:7334
         - [2001:0db8:85a3:0000:0000:8a2e:0370:7334]
         - [2001:0db8:85a3:0000:0000:8a2e:0370:7334]]
         - [2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443
         - [2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443]

        :param column: str
        :return: tuple (
                ip str,
                /32 ipaddress.IPv4Network or /128 ipaddress.IPv6Network) or
                (None, None)
        """

        # first we try if the whole column is just the ip
        try:
            ip = ipaddress.ip_network(column)
            return column, ip
        except ValueError:
            # then we try if the ip has the port appended and/or a trailing ']'
            try:
                # strip additional ']' from column. Ugly but functional
                if (column.startswith("[") and column.endswith("]]")) or (
                    not column.startswith("[") and column.endswith("]")
                ):
                    column = column[:-1]

                parsed = urlparse("//{}".format(column))
                new_column = parsed.hostname
                ip = ipaddress.ip_network(new_column)
                return new_column, ip
            except Exception as e:
                logger.warning(e)
                return None, None

    def truncate_address(self, ip):
        """
        Do the actual masking of the IP address

        :param ip: ipaddress object
        :return: ipaddress object
        """
        if ip.version == 4:
            prefix = 32 - self.ipv4mask
        else:
            prefix = 128 - self.ipv6mask

        return ip.supernet(new_prefix=prefix)[0]


def _validate_ipmask(mask, bits=32):
    """
    Verify if the supplied ip mask is valid.

    :param mask: the provided ip mask
    :param bits: 32 for ipv4, 128 for ipv6
    :return: int
    """
    msg = "must be an integer between 1 and {}".format(bits)
    try:
        mask = int(mask)
    except ValueError:
        raise argparse.ArgumentTypeError(msg)

    if not 0 < mask <= bits:
        raise argparse.ArgumentTypeError(msg)

    return mask


def _validate_integer_ht_0(value):
    """
    Validate if given string is a number higher than 0.

    :param value: str or int
    :return: int
    """
    msg = "must be a positive integer"
    try:
        value = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(msg)
    if not value >= 1:
        raise argparse.ArgumentTypeError(msg)
    return value


def parse_arguments(args):
    """
    Parse all given arguments.

    :param args: list
    :return: argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Example-usage in apache-config:\n"
        'CustomLog "| /path/to/anonip.py '
        '[OPTIONS] --output /path/to/log" '
        "combined\n ",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-4",
        "--ipv4mask",
        metavar="INTEGER",
        help="truncate " "the last n bits (default: %(default)s)",
        type=lambda x: _validate_ipmask(x, 32),
    )
    parser.set_defaults(ipv4mask=12)
    parser.add_argument(
        "-6",
        "--ipv6mask",
        type=lambda x: _validate_ipmask(x, 128),
        metavar="INTEGER",
        help="truncate the last n bits " "(default: %(default)s)",
    )
    parser.set_defaults(ipv6mask=84)
    parser.add_argument(
        "-i",
        "--increment",
        metavar="INTEGER",
        type=lambda x: _validate_integer_ht_0(x),
        help="increment the IP address by n (default: " "%(default)s)",
    )
    parser.set_defaults(increment=0)
    parser.add_argument("-o", "--output", metavar="FILE", help="file to write to")
    parser.add_argument(
        "-c",
        "--column",
        metavar="INTEGER",
        dest="columns",
        nargs="+",
        type=lambda x: _validate_integer_ht_0(x),
        help="assume IP address is in column n (1-based " "indexed; default: 1)",
    )
    parser.set_defaults(column=[1])
    parser.add_argument(
        "-l",
        "--delimiter",
        metavar="STRING",
        type=str,
        help='log delimiter (default: " ")',
    )
    parser.set_defaults(delimiter=" ")
    parser.add_argument(
        "-r",
        "--replace",
        metavar="STRING",
        help="replacement string in case address parsing fails" " Example: 0.0.0.0)",
    )
    parser.add_argument(
        "-p",
        "--skip-private",
        dest="skip_private",
        action="store_true",
        help="do not mask addresses in private ranges. "
        "See IANA Special-Purpose Address Registry.",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="print " "debug messages"
    )
    parser.add_argument("-v", "--version", action="version", version=__version__)

    args = parser.parse_args(args)

    return args


def main():
    """
    Main CLI function for anonip.
    """
    args = parse_arguments(sys.argv[1:])

    if args.debug:
        logger.level = logging.DEBUG
    else:
        logger.level = logging.WARNING

    anonip = Anonip(
        args.columns,
        args.ipv4mask,
        args.ipv6mask,
        args.increment,
        args.delimiter,
        args.replace,
        args.skip_private,
    )

    if args.output:
        try:
            with open(args.output, "a") as output_file:
                for line in anonip.run():
                    output_file.write("{}\n".format(line))
                    output_file.flush()
        except IOError as err:  # pragma: no cover
            logger.error(err)
    else:
        for line in anonip.run():
            print(line)


if __name__ == "__main__":  # pragma: no cover
    main()

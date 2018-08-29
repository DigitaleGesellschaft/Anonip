#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
An ip address anonymizer
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

from __future__ import unicode_literals, print_function
import sys
import os
from io import open
import argparse
try:
    import ipaddress
except ImportError:
    # Could happen with python < 3.3
    print("\033[31;1mError: Module ipaddress not found.\033[0m",
          file=sys.stderr)
    sys.exit(1)
import logging
from grp import getgrnam
from pwd import getpwnam


__title__ = 'anonip'
__description__ = 'Anonip is a tool to anonymize IP-addresses in log-files.'
__version__ = '0.6.0'
__license__ = 'BSD'
__author__ = 'Digitale Gesellschaft'

logger = logging.getLogger(__name__)


class Anonip(object):
    def __init__(self,
                 columns=None,
                 ipv4mask=12,
                 ipv6mask=84,
                 increment=0,
                 replace=None):
        """
        Main class for anonip.

        :param columns: list of ints
        :param ipv4mask: int
        :param ipv6mask: int
        :param increment: int
        :param replace: str
        """
        self.columns = columns if columns else [1]
        self.ipv4mask = ipv4mask
        self.ipv6mask = ipv6mask
        self.increment = increment
        self.replace = replace

    def run(self):
        """
        Generator that reads from stdin and loops forever.

        Yields anonymized log lines.

        :return: None
        """
        while 1:
            try:
                line = sys.stdin.readline()
            except IOError as err:
                # if reading from stdin fails, exit
                logger.warning(err)
                break
            except KeyboardInterrupt:
                break
            else:
                line = line.rstrip()

            # if line couldn't be read (e.g. when EOF has been received)
            # exit the loop
            if not line:
                break

            # ignore empty lines
            if line == '\n':
                continue

            logger.debug('Got line: {}'.format(line))

            yield self.process_line(line)

    def process_line(self, line):
        """
        This function processes a single line.

        It returns the anonymized log line as string.
        """
        loglist = line.split(" ")

        for index in self.columns:
            decindex = index - 1
            try:
                loglist[decindex]
            except IndexError:
                logger.warning('Column {} does not exist!'.format(self.columns))
                continue
            else:
                loglist[decindex] = self.handle_ip_column(loglist[decindex])

        return " ".join(loglist)

    def handle_ip_column(self, raw_ip):
        """
        This function extracts the ip from the column and returns the whole
        column with the ip anonymized.
        """
        try:
            ip = ipaddress.ip_address(raw_ip)
        except Exception as e:
            logger.warning(e)
            if self.replace:
                logger.warning('Using replacement string.')
                return self.replace
            else:
                return raw_ip

        trunc_ip = self.truncate_address(ip)

        if self.increment:
            trunc_ip = trunc_ip + self.increment

        return str(trunc_ip)

    def truncate_address(self, ip):
        """
        Do the actual masking of the IP addresses
        :param ip: ipaddress object
        :return: ipaddress object
        """
        if ip.version == 4:
            mask = 32 - self.ipv4mask
        else:
            mask = 128 - self.ipv6mask

        trunc_ip = ipaddress.ip_interface(
            '{}/{}'.format(ip, mask)).network.network_address

        return trunc_ip


def _verify_ipv4mask(parser, arg):
    """
    Verifies if the supplied ipv4 mask is valid.
    """
    msg = '--ipv4mask must be in between 1 and 32'
    try:
        mask = int(arg)
    except ValueError:
        parser.error(msg)
        return

    if not 0 < mask <= 32:
        parser.error(msg)
        return

    return mask


def _verify_ipv6mask(parser, arg):
    """
    Verify if the supplied ipv6 mask is valid.
    """
    msg = '--ipv6mask must be in between 1 and 128'
    try:
        mask = int(arg)
    except ValueError:
        parser.error(msg)
        return

    if not 0 < mask <= 128:
        parser.error(msg)
        return

    return mask


def _verify_integer_ht_1(parser, value, name):
    """
    Verifies if the supplied column and increment are valid.
    """
    msg = '--{} must be a positive integer'.format(name)
    try:
        value = int(value)
    except ValueError:
        parser.error(msg)
    if not value >= 1:
        parser.error(msg)
    return value


def _verify_increment(parser, increment):
    value = _verify_integer_ht_1(parser, increment, 'increment')
    if value > 2844131327:
        parser.error("--increment must be an integer between 1 and "
                     "2844131327")
    return value


def switch_user(parser, user):
    """
    Switch UID
    """
    try:
        userdb = getpwnam(user)
        os.setuid(userdb.pw_uid)
    except KeyError:
        parser.error('user "{}" does not exist'.format(user))

    except OSError:
        parser.error('could not setuid to "{}"'.format(user))


def switch_group(parser, group):
    """
    Switch GID
    """
    try:
        groupdb = getgrnam(group)
        os.setgid(groupdb.gr_gid)

    except KeyError:
        parser.error('group "{}" does not exist'.format(group))

    except OSError:
        parser.error('could not setgid to "{}"'.format(group))


def set_umask(parser, umask):
    """
    Set umask.
    """
    try:
        # use int(umask, 8) in order to not cut the leading zeros
        os.umask(int(umask, 8))
    except (SyntaxError, TypeError, ValueError):
        parser.error('"{}" is not a valid umask'.format(umask))


def parse_arguments():
    """
    Parse all given arguments.
    """
    parser = argparse.ArgumentParser(description='An ip address anonymizer.',
                                     epilog='Example-usage in apache-config:\n'
                                     'CustomLog "| /path/to/anonip.py '
                                     '[OPTIONS] --output /path/to/log" '
                                     'combined\n ', formatter_class=argparse.
                                     RawDescriptionHelpFormatter)

    parser.add_argument('-4', '--ipv4mask', metavar='INTEGER', help='truncate '
                        'the last n bits (default: %(default)s)',
                        type=lambda x: _verify_ipv4mask(parser, x))
    parser.set_defaults(ipv4mask=12)
    parser.add_argument('-6', '--ipv6mask',
                        type=lambda x: _verify_ipv6mask(parser, x),
                        metavar='INTEGER', help='truncate the last n bits '
                        '(default: %(default)s)')
    parser.set_defaults(ipv6mask=84)
    parser.add_argument('-i', '--increment', metavar='INTEGER',
                        type=lambda x: _verify_increment(parser, x),
                        help='increment the IP address by n (default: '
                        '%(default)s)')
    parser.set_defaults(increment=0)
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='file to write to')
    parser.add_argument('-c', '--column', metavar='INTEGER', dest='columns',
                        nargs='+',
                        type=lambda x: _verify_integer_ht_1(parser, x,
                                                            'column'),
                        help='assume IP address is in column n (default: 1)')
    parser.set_defaults(column=[1])
    parser.add_argument('-r', '--replace', metavar='STRING',
                        help='replacement string in case address parsing fails'
                        ' Example: 0.0.0.0)')
    parser.set_defaults(replace=None)
    parser.add_argument('-u', '--user', metavar='USERNAME',
                        help='switch user id',
                        type=str)
    parser.add_argument('-g', '--group', metavar='GROUPNAME',
                        help='switch group id',
                        type=str)
    parser.add_argument('-m', '--umask', metavar='UMASK',
                        help='set umask',
                        type=lambda x: set_umask(parser, x))
    parser.add_argument('-d', '--debug', action='store_true', help='print '
                        'debug messages')
    parser.add_argument('-v', '--version', action='version',
                        version=__version__)

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig()

    if args.group:
        switch_group(parser, args.group)

    if args.user:
        switch_user(parser, args.user)

    return args


def main():
    """
    Main CLI function for anonip.
    """

    args = parse_arguments()

    anonip = Anonip(args.columns,
                    args.ipv4mask,
                    args.ipv6mask,
                    args.increment,
                    args.replace)

    if args.output:
        try:
            with open(args.output, "a") as output_file:
                for line in anonip.run():
                    output_file.write("{}\n".format(line))
                    output_file.flush()
        except IOError as err:
            logger.error(err)
    else:
        for line in anonip.run():
            print(line)


if __name__ == "__main__":
    main()

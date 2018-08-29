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

logger = logging.getLogger('anonip')


def read_stdin(args, output_file=None):
    """
    This function reads from stdin and loops forever.
    Output is either written to stdout or the file specified as argument.
    The function does not return as it should loop forever.

    :param args: argparse.Namespace
    :param output_file: _io.TextIOWrapper
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

        if args.debug:
            logger.debug('Got line: {}'.format(line))

        # parse the line
        parsed_line = parse_line(line, args)

        # decide where to write the result to ... either stdin or the specified
        # output file
        if output_file:
            output_file.write("{}\n".format(parsed_line))
            output_file.flush()
        else:
            print(parsed_line)


def truncate_address(ip, ipv4mask, ipv6mask):
    if ip.version == 4:
        mask = 32 - ipv4mask
    else:
        mask = 128 - ipv6mask

    trunc_ip = ipaddress.ip_interface(
        '{}/{}'.format(ip, mask)).network.network_address

    return trunc_ip


def handle_ip_column(raw_ip, ipv4mask, ipv6mask, increment, replace=None):
    """
    This function extracts the ip from the column and returns the whole column
    with the ip anonymized.
    """
    try:
        ip = ipaddress.ip_address(raw_ip)
    except Exception as e:
        logger.warning(e)
        if replace:
            logger.warning('Using replacement string.')
            return replace
        else:
            return raw_ip

    trunc_ip = truncate_address(ip, ipv4mask, ipv6mask)

    if increment:
        trunc_ip = trunc_ip + increment

    return str(trunc_ip)


def parse_line(line, args):
    """
    This function parses a single line.
    As the user can specify --column, the function needs to select the right
    column(s) according to set argument.
    It returns the anonymized log line as string.
    """
    loglist = line.split(" ")

    for index in args.column:
        decindex = index - 1
        try:
            loglist[decindex]
        except IndexError:
            logger.warning('Column {} does not exist!'.format(args.column))
            continue
        else:
            loglist[decindex] = handle_ip_column(loglist[decindex],
                                                 args.ipv4mask,
                                                 args.ipv6mask,
                                                 args.increment,
                                                 args.replace)

    # return without newline at the end and also remove trailing whitespaces
    return " ".join(loglist)


def verify_ipv4mask(parser, arg):
    """
    Verifies if the supplied ipv4 mask is valid.
    """
    try:
        mask = int(arg)
    except ValueError:
        parser.error("--ipv4mask must be in between 1 and 32")
        return

    if not 0 < mask <= 32:
        parser.error("--ipv4mask must be in between 1 and 32")
        return

    return mask


def verify_ipv6mask(parser, arg):
    """
    Verify if the supplied ipv6 mask is valid.
    """
    try:
        mask = int(arg)
    except ValueError:
        parser.error("--ipv6mask must be in between 1 and 128")
        return

    if not 0 < mask <= 128:
        parser.error("--ipv6mask must be in between 1 and 128")
        return

    return mask


def verify_integer_ht_1(parser, value, name):
    """
    Verifies if the supplied column and increment are valid.
    """
    try:
        value = int(value)
    except ValueError:
        parser.error('--{} must be an integer'.format(name))
    if not value >= 1:
        parser.error('--{} must be an integer, 1 or higher'.format(name))
    return value


def verify_increment(parser, increment):
    value = verify_integer_ht_1(parser, increment, 'increment')
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


def check_umask(parser, umask):
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
                        type=lambda x: verify_ipv4mask(parser, x))
    parser.set_defaults(ipv4mask=12)
    parser.add_argument('-6', '--ipv6mask',
                        type=lambda x: verify_ipv6mask(parser, x),
                        metavar='INTEGER', help='truncate the last n bits '
                        '(default: %(default)s)')
    parser.set_defaults(ipv6mask=84)
    parser.add_argument('-i', '--increment', metavar='INTEGER',
                        type=lambda x: verify_increment(parser, x),
                        help='increment the IP address by n (default: '
                        '%(default)s)')
    parser.set_defaults(increment=0)
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='file to write to')
    parser.add_argument('-c', '--column', metavar='INTEGER', nargs='+',
                        type=lambda x: verify_integer_ht_1(parser, x,
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
                        type=lambda x: check_umask(parser, x))
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
    Prepares the script before the endless parsing loop starts.
    """
    args = parse_arguments()

    if args.output:
        try:
            with open(args.output, "a") as output_file:
                read_stdin(args, output_file)
        except IOError as err:
            logger.error(err)
    else:
        read_stdin(args)


if __name__ == "__main__":
    main()

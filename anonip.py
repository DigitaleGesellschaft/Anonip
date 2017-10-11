#! /usr/bin/env python2

"""
anonip.py 0.5:
An ip address anonymizer
Swiss Privacy Foundation
http://www.privacyfoundation.ch/
Special thanks to: Thomas B. and Fabio R.

Copyright (c) 2013, 2014, Swiss Privacy Foundation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the Swiss Privacy Foundation nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE SWISS PRIVACY FOUNDATION BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import sys
import os

from socket import inet_pton, inet_ntop, AF_INET, AF_INET6, error as sockerror
from struct import unpack, pack
import argparse
from signal import signal, SIGTERM, SIGQUIT, SIGINT

from grp import getgrnam
from pwd import getpwnam


def read_stdin(config):
    """
    This function reads from stdin and loops forever.
    Output is either written to stdout or the file specified as argument.
    The function does not return as it should loop forever.
    """
    while 1:
        try:
            line = sys.stdin.readline()
        except IOError as err:
            # if reading from stdin fails, exit
            print >> sys.stderr, err
            cleanup(config)
            break

        # if line couldn't be read (e.g. when EOF has been received)
        # exit the loop
        if not line:
            break

        # ignore empty lines
        if line == '\n':
            continue

        if config.debug:
            print >> sys.stderr, ("[debug] read %s, calling parse_line"
                                  % (line.rstrip()))

        # parse the line
        parsed_line = parse_line(line, config)

        # decide where to write the result to ... either stdin or the specified
        # output file
        if config.output:
            config.output.write("%s\n" % parsed_line)
            config.output.flush()
        else:
            print parsed_line.rstrip()


def handle_ip_column(column, config):
    """
    This function extracts the ip from the column and returns the whole column
    with the ip anonymized.
    """
    valid = ["A", "B", "C", "D", "E", "F",
             "a", "b", "c", "d", "e", "f",
             ".", ":", "0", "1", "2", "3",
             "4", "5", "6", "7", "8", "9"]

    array = list(column)
    first = 0
    amount = 0
    last = len(array)
    togglefirst = True
    togglelast = True

    # search for valid chars of IP-adresses. The found string must consist of
    # at least 7 chars.
    for index, char in enumerate(array):
        if char in valid:
            togglefirst = False
            amount += 1
            continue

        if togglefirst is True:
            first = index + 1
        else:
            if amount < 7:
                amount = 0
                first = index + 1
            else:
                if togglelast:
                    minus = last - index
                    last -= minus
                    togglelast = False

    replacement = truncate_address("".join(array[first:last]), config)

    # Check for a given replace-string and handle the return of the column.
    # An empty replacement automatically means there is no replace-string set.
    if replacement:
        if ((config.replace and config.replace not in replacement) or
                not config.replace):
            return "%s%s%s" % ("".join(array[:first]), replacement,
                               "".join(array[last:]))
        else:
            return config.replace
    else:
        return column


def parse_line(log, config):
    """
    This function parses a single line.
    As the user can specify --column, the function needs to select the right
    column(s) according to set argument.
    It returns the anonymized log line as string.
    """
    loglist = log.split(" ")

    for index in config.column:
        decindex = index - 1
        try:
            loglist[decindex]
        except IndexError:
            # Do nothing
            pass
        else:
            loglist[decindex] = handle_ip_column(loglist[decindex], config)

    # return without newline at the end and also remove trailing whitespaces
    return "%s" % " ".join(loglist).rstrip()


def pton_unpack4(address):
    """
    Converts IPv4 address to int.
    Requires a string, returns a 32 bit int.
    """
    try:
        pton = inet_pton(AF_INET, address)
    except sockerror:
        return None

    unpacked = unpack("!I", pton)

    return unpacked[0]


def pton_unpack6(address):
    """
    Converts IPv6 address to int.
    Requires a string, returns a 128 bit int.
    """
    try:
        pton = inet_pton(AF_INET6, address)
    except sockerror:
        return None

    unpacked = unpack("!QQ", pton)

    return (unpacked[0] << 64) | unpacked[1]


def ntop_pack4(address):
    """
    Converts int to IPv4 address.
    Requires a 32 bit int, returns a string.
    """
    packed = pack("!I", address)

    return inet_ntop(AF_INET, packed)


def ntop_pack6(address):
    """
    Converts int to IPv6 address.
    Requires a 128 bit int, returns a string.
    """
    packed = pack("!QQ", address >> 64, address & (2**64 - 1))

    return inet_ntop(AF_INET6, packed)


def truncate_address(address, config):
    """Truncates the ip addresses"""
    # try ipv4 first....
    family = AF_INET
    addr_pton = pton_unpack4(address)

    if addr_pton is None:
        # if we got no result, try again with IPv6
        family = AF_INET6
        addr_pton = pton_unpack6(address)

        if addr_pton is None:
            # if it still didn't work out, return the generic replacement
            # string
            return config.replace

    # AND the ip address and the mask, to truncate the address
    if family == AF_INET:
        s_addr_output = addr_pton & config.ipv4_netmask
    elif family == AF_INET6:
        s_addr_output = addr_pton & config.ipv6_netmask
    else:
        # this shouldnt happen ... handle it anyway
        return config.replace

    # should we increment?
    if config.increment > 0:
        s_addr_output += config.increment

    # return the IP address as a string
    if family == AF_INET:
        return ntop_pack4(s_addr_output)
    elif family == AF_INET6:
        return ntop_pack6(s_addr_output)
    else:
        # this shouldn't happen ... handle it anway
        return config.replace


def verify_ipv4mask(parser, arg):
    """
    Verifies if the supplied ipv4 mask is valid.
    """
    try:
        mask = int(arg)
    except ValueError:
        parser.error("--ipv4mask must be in between 1 and 32")

    if not 0 < mask <= 32:
        parser.error("--ipv4mask must be in between 1 and 32")

    return mask


def verify_ipv6mask(parser, arg):
    """
    Verify if the supplied ipv6 mask is valid.
    """
    try:
        mask = int(arg)
    except ValueError:
        parser.error("--ipv6mask must be in between 1 and 128")

    if not 0 < mask <= 128:
        parser.error("--ipv6mask must be in between 1 and 128")

    return mask


def verify_integer(parser, arg, htzero):
    """
    Verifies if the supplied column and increment are valid.
    """
    try:
        arg = int(arg)
    except ValueError:
        if htzero:
            parser.error("--column must be an integer, 1 or higher")
        else:
            parser.error("--increment must be an integer")
    if htzero:
        if not arg >= 1:
            parser.error("--column must be an integer, 1 or higher")
    else:
        if not arg >= 0 or arg > 2844131327:
            parser.error("--increment must be an integer between 1 and "
                         "2844131327")
    return arg


def open_output_file(parser, args):
    """
    Opens the specified output file.
    """
    try:
        output_file = open(args.output, "a")
    except IOError as err:
        parser.error("%s" % err)

    if args.debug:
        print >> sys.stderr, "[debug] opened output file %s" % args.output

    return output_file


def switch_user(parser, user):
    """
    Try to switch UID
    """
    try:
        userdb = getpwnam(user)
        os.setuid(userdb.pw_uid)
    except KeyError:
        parser.error("user %s does not exist" % user)

    except OSError:
        parser.error("could not setuid to %s" % user)
    return user


def switch_group(parser, group):
    """
    Try to switch GID
    """
    try:
        groupdb = getgrnam(group)
        os.setgid(groupdb.gr_gid)

    except KeyError:
        parser.error("group %s does not exist" % group)

    except OSError:
        parser.error("could not setgid to %s" % group)
    return group


def check_umask(parser, umask):
    """
    If the user has specified a umask, set it.
    """
    try:
        # use int(umask, 8) in order to not cut the leading zeros
        os.umask(int(umask, 8))
    except (SyntaxError, TypeError, ValueError):
        parser.error("%s is not a valid umask" % umask)
    return umask


def parse_arguments():
    """
    Parse all given arguments.
    """
    parser = argparse.ArgumentParser(description='An ip address anonymizer.',
                                     epilog="Example-usage in apache-config:\n"
                                     "CustomLog \"| /path/to/anonip.py "
                                     "[OPTIONS] --output /path/to/log\" "
                                     "combined\n ", formatter_class=argparse.
                                     RawDescriptionHelpFormatter)

    parser.add_argument("-d", "--debug", dest="debug",
                              action="store_true", help="debug")
    parser.add_argument('--ipv4mask', metavar='N', help='truncate the last N '
                        'bits (default: %(default)s)',
                        type=lambda x: verify_ipv4mask(parser, x))
    parser.set_defaults(ipv4mask=12)
    parser.add_argument('--ipv6mask',
                        type=lambda x: verify_ipv6mask(parser, x),
                        metavar='N', help='truncate the last N bits (default: '
                        '%(default)s)')
    parser.set_defaults(ipv6mask=84)
    parser.add_argument('--increment', metavar='N',
                        type=lambda x: verify_integer(parser, x, False),
                        help='increment the IP address by N (default: '
                        '%(default)s)')
    parser.set_defaults(increment=0)
    parser.add_argument("--output", dest="output", metavar="FILE",
                        help="write to file (default: %(default)s)")
    parser.set_defaults(output=None)
    parser.add_argument('--column', metavar='N', nargs='+',
                        type=lambda x: verify_integer(parser, x, True),
                        help='assume IP address is in column n (default: '
                        '%(default)s)')
    parser.set_defaults(column=1)
    parser.add_argument('--replace', metavar='STRING',
                        help='replacement string in case address parsing fails '
                        '(default: %(default)s. Example: 0.0.0.0)')
    parser.set_defaults(replace=None)
    parser.add_argument('--user', metavar='USERNAME',
                        help='switch user id',
                        type=lambda x: switch_user(parser, x))
    parser.set_defaults(user=None)
    parser.add_argument('--group', metavar='GROUPNAME',
                        help='switch group id',
                        type=lambda x: switch_group(parser, x))
    parser.set_defaults(group=None)
    parser.add_argument('--umask', metavar='UMASK',
                        help='set umask',
                        type=lambda x: check_umask(parser, x))
    parser.set_defaults(umask=None)

    args = parser.parse_args()
    try:
        int(args.column)
    except TypeError:
        pass
    else:
        args.column = [args.column]

    # open file descriptor after parsing the arguments, in order to set the
    # right user, group and/or umask
    if args.output:
        args.output = open_output_file(parser, args)

    return args


def cleanup(config):
    """
    This function cleans up before the script exits.
    Currently, it does only close the open file descriptor.
    """
    if config.output:
        config.output.close()

        if config.debug:
            print >> sys.stderr, "[debug] closed output file %s" % config.output.name


def cleanup_handler(signum, config):
    """
    This is a wrapper around cleanup(), which is used to be specified as a
    signal handler.
    """
    print >> sys.stderr, "\ncaught signal %i, terminating..." % signum
    cleanup(config)
    sys.exit(1)


def main():
    """
    Prepares the script before the endless parsing loop starts.
    """
    # assign a signal handler, that should clean up if the script
    # needs to exit
    bound_cleanup_handler = lambda signum, frame: cleanup_handler(signum,
                                                                  config)
    signal(SIGTERM, bound_cleanup_handler)
    signal(SIGQUIT, bound_cleanup_handler)
    signal(SIGINT, bound_cleanup_handler)

    config = parse_arguments()

    # calculate the v4 and v6 netmask that will be used to anonymize
    # ip addresses. this is done inside the main function as it should
    # be done only once. the result can be re-used by other functions.
    ipv4_full_netmask = pton_unpack4('255.255.255.255')
    config.ipv4_netmask = ipv4_full_netmask << config.ipv4mask

    ipv6_full_netmask = pton_unpack6('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
    config.ipv6_netmask = ipv6_full_netmask << config.ipv6mask

    # start looping over the standard input
    read_stdin(config)

    # should the loop exit, try to cleanup
    cleanup(config)

    # bye, bye
    sys.exit(0)


if __name__ == "__main__":
    main()

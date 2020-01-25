# anonip

[![PyPI](https://img.shields.io/pypi/v/anonip.svg)](https://pypi.org/project/anonip/)
[![Python versions](https://img.shields.io/pypi/pyversions/anonip.svg)](https://pypi.org/project/anonip/)
[![Build Status](https://github.com/DigitaleGesellschaft/Anonip/workflows/Tests/badge.svg)](https://github.com/DigitaleGesellschaft/Anonip/actions?query=workflow%3ATests)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/DigitaleGesellschaft/Anonip/blob/master/setup.cfg#L58)
[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/DigitaleGesellschaft/Anonip)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

Digitale Gesellschaft
https://www.digitale-gesellschaft.ch


Formerly
Swiss Privacy Foundation
https://www.privacyfoundation.ch/


## Description

Anonip is a tool to anonymize IP addresses in log files.

It masks the last bits of IPv4 and IPv6 addresses. That way most of the
relevant information is preserved, while the IP-address does not match a
particular individuum anymore.

Depending on your webserver software, the log entries may directly get piped
to Anonip. The unmasked IP addresses will never be written to any file.

Using shell redirects, it's also possible to rewrite existing log files.

## Features

 - Masks IP addresses in log files
 - Configurable amount of masked bits
 - The column containing the IP address can freely be chosen
 - Works for both access.log- and error.log files

## Officially supported python versions

 - 2.7
 - 3.5
 - 3.6
 - 3.7
 - 3.8

## Dependencies
If you're using python version >=3.3, there are no external
dependencies.

For python versions <3.3:
 - [ipaddress module](https://github.com/kwi-dk/py2-ipaddress)

## Invocation

```
usage: anonip.py [-h] [-4 INTEGER] [-6 INTEGER] [-i INTEGER] [-o FILE]
                 [--input FILE] [-c INTEGER [INTEGER ...]] [-l STRING]
                 [-r STRING] [-p] [-d] [-v]

Anonip is a tool to anonymize IP-addresses in log files.

optional arguments:
  -h, --help            show this help message and exit
  -4 INTEGER, --ipv4mask INTEGER
                        truncate the last n bits (default: 12)
  -6 INTEGER, --ipv6mask INTEGER
                        truncate the last n bits (default: 84)
  -i INTEGER, --increment INTEGER
                        increment the IP address by n (default: 0)
  -o FILE, --output FILE
                        file to write to
  --input FILE          File or FIFO to read from (default: stdin)
  -c INTEGER [INTEGER ...], --column INTEGER [INTEGER ...]
                        assume IP address is in column n (1-based indexed;
                        default: 1)
  -l STRING, --delimiter STRING
                        log delimiter (default: " ")
  -r STRING, --replace STRING
                        replacement string in case address parsing fails
                        (Example: 0.0.0.0)
  -p, --skip-private    do not mask addresses in private ranges. See IANA
                        Special-Purpose Address Registry.
  -d, --debug           print debug messages
  -v, --version         show program's version number and exit
```

## Usage

``` shell
/path/to/anonip.py [OPTIONS] < /path/to/orig_log --output /path/to/log
```
or using shell redirects only (mind the redirected output is appending):
``` shell
/path/to/anonip.py [OPTIONS] < /path/to/orig_log >> /path/to/log
```

### With Apache

In the Apache configuration (or the one of a vhost) the log output needs to
get piped to anonip like this:
```
CustomLog "|/path/to/anonip.py [OPTIONS] --output /path/to/log" combined
ErrorLog  "|/path/to/anonip.py [OPTIONS] --output /path/to/error_log"
```
That's it! All the IP addresses will be masked in the log now.


### With nginx

nginx does not support spawning a process it then pipes to. Thus
you need to create a named pipe (file-based FIFO) and start the
processes yourself, along this lines:
``` shell
mkfifo /path/to/log.fifo /path/to/error_log.fifo
/path/to/anonip.py [OPTIONS] --output /path/to/log < /path/to/log.fifo &
/path/to/anonip.py [OPTIONS] --output /path/to/error_log < /path/to/error_log.fifo &
```
As you can see, you need to start a separate process for each access-log
file and for each error-log file.

In the nginx configuration (or the one of a vhost) the log output
needs to be set to the named pipe like this:
```
access_log /path/to/log.fifo;
error_log  /path/to/error_log.fifo;
```

### As a python module

Read from stdin:
``` python
from anonip import Anonip

anonip = Anonip()
for line in anonip.run():
    print(line)

```

Manually feed lines:
``` python
from anonip import Anonip

data = ['1.1.1.1', '2.2.2.2', '3.3.3.3']
anonip = Anonip()
for line in data:
    print(anonip.process_line(line))

```

### Python 2 or 3?
For compatibility reasons, anonip uses the shebang `#! /usr/bin/env python`.
This will default to python2 on all Linux distributions except for Arch Linux.
The performance of anonip can be improved by running it with python3. If
python3 is available on your system, you should preferrably invoke anonip
like this:

``` shell
python3 -m anonip [OPTIONS]
```

or

``` shell
python3 /path/to/anonip.py [OPTIONS]
```

## Motivation

In most cases IP addresses are personal data as they refer to individuals (or at least
their Internet connection). IP addresses - and the data associated with them - may
therefore only be lawfully processed in accordance with the principles of the
applicable data protection laws.

Storage of log files from web servers, for example, is only permitted within close time
limits or with the voluntary consent of the persons concerned (as long as the
information about the IP address is linkable to a person).

Anonip tries to avoid exactly that, but without losing the benefit of those log files.

With the masking of the last bits of IP addresses, we're still able to distinguish the
log entries up to a certain degree. Compared to the entire removal of the IP-adresses,
we're still able to make a rough geolocating as well as a reverse DNS lookup. But the
otherwise distinct IP addresses do not match a particular individuum anymore.

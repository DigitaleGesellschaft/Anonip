# anonip.py

Digitale Gesellschaft
https://www.digitale-gesellschaft.ch


formerly
Swiss Privacy Foundation
https://www.privacyfoundation.ch/


## DESCRIPTION

Anonip is a tool to anonymize IP-addresses in log-files.

It masks the last bits of IPv4- and IPv6-addresses. That way most of the
relevant information is preserved, while the IP-address does not match a
particular individuum anymore.

The log-entries get directly piped from Apache to Anonip. The unmasked IP-
addresses are never written to any file.

With the help of cat, it's also possible, to rewrite existing log-files.

## FUNCTIONS

 - Masks IP-addresses in log-files
 - Configurable amount of masked bits
 - The column containing the IP-address can freely be chosen
 - Works for both access.log- and error.log-files

## OPTIONS
```
  -h, --help          show this help message and exit
  -d, --debug         debug
  --ipv4mask N        truncate the last N bits (default: 12)
  --ipv6mask N        truncate the last N bits (default: 84)
  --increment N       increment the IP address by N (default: 0)
  --output FILE       write to file (default: None)
  --column N [N ...]  assume IP address is in column n (default: 1)
  --replace STRING    replacement string in case address parsing fails
                      (default: None. Example: 0.0.0.0)
  --user USERNAME     switch user id
  --group GROUPNAME   switch group id
  --umask UMASK       set umask
```

## USAGE

In the Apache configuration (or the one of the vhost) the log-output needs to
get piped to anonip:
```
CustomLog "|/path/to/anonip.py [OPTIONS] --output /path/to/log" combined
```
That's it! All the IP-addresses will be masked in the log now.

Alternative:
```
cat /path/to/orig_log | /path/to/anonip.py [OPTIONS] --output /path/to/log
```
## MOTIVATION

In a time, where the mass-data-collection of certain companies and
organisations gets more and more obvious, it's crutial to realize, that also
we maintain unnecessary huge data-collections.

For example admins of webservers. In the log-files you can find all the IP-
addresses of all visitors in cleartext and all of a sudden we possess a huge
collection of personalized data.

Anonip tries to avoid exactly that, but without losing the undisputed benefit
of those log-files.

With the masking of the last bits of IP-addresses, we're still able to
distinguish them up to a certain degree. Compared to the entire removal of the
IP-adresses, we're still able to make a rough geolocating as well as a reverse
DNS lookup. But the otherwise distinct IP-addresses do not match a particular
individuum anymore.

#!/usr/bin/env python3
"""check_sip

Usage: check_sip -H <host> -w <warnval> -c <critval>

Options:

  -h --help     Show this help screen.
  -H --host     Set the target host.
  -w --warn     Set the warning value for ping times.
  -c --crit     Set the critical value for ping times.

Support:

  For technical support, file a support issue at:
"""


import sys
import socket
from docopt import docopt

if __name__ == '__main__':
    arguments = docopt(__doc__, version='Naval Fate 2.0')
    print(arguments)
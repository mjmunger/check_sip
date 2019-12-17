#!/usr/bin/env python3
"""check_sip

Usage: check_sip -H HOST -p PORT -w WARNVAL -c CRITVAL [-l CLIENTHOST -f FROMPEER -o CLIENTPORT -n -i -d -g LOGFILE]

Options:

  -h  Show this help screen.
  -H HOST        Set the target host.
  -w WARNVAL     Set the warning value for ping times.
  -c CRITVAL     Set the critical value for ping times.
  -l CLIENTHOST  Set the client hostname to override what gethostname() is returning.
  -O CLIENTPORT  Set the port on which this machine is expecting replies.
  -f FROMPEER    Set the "from" peer in the request. (Defaults to watch)
  -p PORT        Set the remote port on which the remote host is listening to SIP requests.
  -n             Tells the script that responses should be NAT'd. (Sets rport in SIP Via)
  -i             Tells the script to use the IP address of the client server in the SIP payload instead of a domain.
  -d             Dump the request and response to stdout
  -g LOGFILE     Append the request and response to the specified log file.

Support:

  For technical support, file a support issue at: https://github.com/mjmunger/check_sip
"""


import sys
from IPy import IP
import socket
import random
from docopt import docopt

class TagGenerator:
    chars = None
    tag = None

    def __init__(self):
        self.chars = list("abcdefghijklmnopqrstuvwxyz0123456789")
        tag = ""
        for i in range(0, 10):
            tag = tag + self.chars[random.randrange(0, len(self.chars))]

        self.tag = tag

    def __str__(self):
        return self.tag


class SipRequest:

    options = None
    rport = None
    from_peer = None
    dest_uri = None
    dest_port = None
    id_tag = None
    client_host = None
    client_port = None
    version = "1.0"
    tag = None
    payload = None
    verbosity = 0
    branch = None

    def __init__(self, tag, branch):
        self.id_tag = tag.tag
        self.branch = branch.tag

    def set_verbosity(self, level):
        self.verbosity = level

    def build_packet(self):
        buffer = []
        buffer.append("OPTIONS {0} SIP/2.0".format(self.dest_uri))
        buffer.append("Via: SIP/2.0/UDP {0}:{1};branch={2};{3}".format(self.client_host, self.client_port, self.branch, self.rport))
        buffer.append("From: sip:{0}@{1}:{2};tag={3}".format(self.from_peer, self.client_host, self.client_port, self.id_tag))
        buffer.append("To: {0}".format(self.dest_uri))
        buffer.append("Call-ID: {0}@{1}".format(self.id_tag, self.client_host))
        buffer.append("CSeq: 1 OPTIONS")
        buffer.append("Contact: sip:{0}@{1}:{2}".format(self.from_peer, self.client_host, self.rport))
        buffer.append("Content-length: 0")
        buffer.append("Max-Forwards: 70")
        buffer.append("User-agent: check_sip {0}".format(self.version))
        buffer.append("Accept: text/plain")

        self.payload = "\n".join(buffer).encode()

    def __str__(self):
        buffer = []
        buffer.append("options: {0}".format(self.options))
        buffer.append("rport: {0}".format(self.rport))
        buffer.append("from_peer: {0}".format(self.from_peer))
        buffer.append("dest_uri: {0}".format(self.dest_uri))
        buffer.append("id_tag: {0}".format(self.id_tag))
        buffer.append("client_host: {0}".format(self.client_host))
        buffer.append("from_peer: {0}".format(self.from_peer))
        buffer.append("version: {0}".format(self.version))
        buffer.append("tag: {0}".format(self.tag))
        buffer.append("payload: {0}".format(self.payload))
        return "\n".join(buffer)


class SipResponse:

    raw_response = None
    response_code = None
    ip_private = None
    contact = None
    require_nat = None
    request = None

    def __init__(self, response):
        self.raw_response = response
        self.parse_response()

    def get_response_field(self, response, target_field):
        for line in response:
            pointer = line.find(":")
            field = line[:pointer]
            value = line[pointer:]

            if target_field.lower() == field.lower():
                return value[1:].strip()

        return False

    def parse_response(self):
        string_response = self.raw_response.decode()
        buffer = string_response.split("\n")
        print("\n".join(buffer))

        self.response_code = int(buffer.pop(0).replace("SIP/2.0", "").strip()[:3])
        self.contact = self.get_response_field(buffer, "Contact")

    def contact_is_private(self):
        buffer = self.contact.split(":")
        print(buffer)
        addr = buffer[1]

        ip = IP(addr)
        return True if ip.iptype() == 'PRIVATE' else False

    def get_status(self):
        if self.contact_is_private() and self.request.rport:
            return 1

        return 0

    def set_request(self, request):
        self.request = request

    def __str__(self):
        buffer = []
        buffer.append("Response Code: {0}".format(self.response_code))
        buffer.append("Contact: {0}".format(self.contact))
        buffer.append("Contact is private: {0}".format("Yes" if self.contact_is_private() else "No"))

        return "\n".join(buffer)


if __name__ == '__main__':
    arguments = docopt(__doc__, version='check_sip 1.0')
    # print(arguments)

    request = SipRequest(TagGenerator(), TagGenerator())
    request.set_verbosity(9)
    request.client_host = arguments['-H'] if arguments['-H'] is not None else socket.gethostname()
    if arguments['-i']:
        request.client_host = socket.gethostbyname(socket.gethostname())
    request.client_port = arguments['CLIENTPORT'] if arguments['CLIENTPORT'] is not None else "5060"
    request.from_peer = arguments['-f'] if arguments['-f'] is not None else "watch"
    request.rport = "rport" if arguments['-n'] else ""
    request.dest_port = arguments['-p'] if arguments['-p'] is not None else "5060"
    request.dest_uri = "sip:watch@pbx.hph.io"
    request.build_packet()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    s.connect((request.client_host, int(request.client_port)))
    s.send(request.payload)
    r = s.recv(512)

    s.close()

    response = SipResponse(r)
    response.set_request(request)
    exit_code = response.get_status()

    if arguments['-g']:
        f = open(arguments['-g'], 'a')
        f.write("---REQUEST---\n")
        f.write(request.payload.decode())
        f.write("\n---REQUEST---\n")
        f.write("----Response---\n")
        f.write(r.decode())
        f.write("----Response---\n")
        f.write("Exit code: {0}\n".format(exit_code))
        f.write("=========================\n")
        f.close()

    sys.exit(exit_code)


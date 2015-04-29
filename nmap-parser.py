#!/usr/bin/env python

import argparse
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

def parse_args():
    ''' Create the arguments '''
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--nmapxml", help="Nmap XML file to parse")
    parser.add_argument("-l", "--hostlist", help="Host list file")
    return parser.parse_args()

def report_parser(report):
    ''' Parse the Nmap XML report '''
    for host in report.hosts:
        ip = host.address

        if host.is_up():
            hostname = 'N/A'
            # Get the first hostname (sometimes there can be multi)
            if len(host.hostnames) != 0:
                hostname = host.hostnames[0]

            print '[*] {0} - {1}'.format(ip, hostname)

            # Get the port and service
            # objects in host.services are NmapService objects
            for s in host.services:

                # Check if port is open
                if s.open():
                    serv = s.service
                    port = s.port
                    ban = s.banner

                    # Perform some action on the data
                    print_data(ip, port, serv, ban)

def print_data(ip, port, serv, ban):
    ''' Do something with the nmap data '''
    if ban != '':
        ban = ' -- {0}'.format(ban)

    print '    {0}: {1}{2}'.format(port, serv, ban)

def main():
    args = parse_args()
    report = NmapParser.parse_fromfile(args.nmapxml)
    report_parser(report)

main()

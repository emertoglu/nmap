#!/usr/bin/env python

import nmap
import sys

nm = nmap.PortScanner()

port_list = [21, 22, 25, 139, 3306, 1248]
host = sys.argv[1]
argument = '-n -T4 -sV -p '
print("Taranacak host : %s " % host)
print ("\n")
print("////////////////////////////////////////////")

print("Port\tName\tState\tReason")

print("////////////////////////////////////////////")

try:

    for i in port_list:
        sc = nm.scan(hosts=host, arguments=argument + str(i))
        print("%s\t%s\t%s\t%s" % (i, nm[host]['tcp'][i]['name'], nm[host]['tcp'][i]['state'], nm[host]['tcp'][i]['r$']))

except KeyboardInterrupt:
    print("\n")
    print("!Tarama Durduruldu!")
    exit

print("\n")

print("Tarama Zamani : %s " % (sc["nmap"]['scanstats']['timestr']))

print("Tarama Suresi : %s " % (sc["nmap"]['scanstats']['elapsed']))

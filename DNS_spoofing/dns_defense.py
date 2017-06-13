#!/usr/bin/env python
# --*-- coding: UTF-8 --*--

__author__ = 'Francisco Javier del Castillo Ramírez'
__version__ = '1.0'
__last_modification__ = '2017.06.09'

import argparse
import logging
import os
from scapy.all import *
import sys, getopt
from collections import deque

cola = deque(maxlen = 10)
paquetes = None
try:
    writer=PcapWriter("temp.pcap")
except:
    pass

def cabecera():
    #Muestro la fecha y hora
    os.system('clear')
    localtime = time.asctime(time.localtime(time.time()))
    print'[ {0} ]'.format(localtime)

def analizar_paquetes(paquete):

    if paquete.haslayer(IP) and paquete.haslayer(UDP) and\
     paquete.haslayer(DNS) and paquete.haslayer(DNSRR):
        if len(cola)>0:
            for p in cola:
                if p[IP].dst == paquete[IP].dst and\
                p[IP].sport == paquete[IP].sport and\
                p[IP].dport == paquete[IP].dport and\
                p[DNSRR].rdata != paquete[DNSRR].rdata and\
                p[DNS].id == paquete[DNS].id and\
                p[DNS].qd.qname == paquete[DNS].qd.qname and\
                p[IP].payload != paquete[IP].payload:
                    print "DNS poisoning attempt detected"
                    print "TXID %s Request URL %s"%( p[DNS].id, p[DNS].qd.qname.rstrip('.'))
                    print "Answer1 [%s]"%p[DNSRR].rdata
                    print "Answer2 [%s]"%paquete[DNSRR].rdata
        cola.append(paquete)



if __name__ == '__main__':

	cabecera()
	try:
		while 1:
			paquetes = sniff(prn=analizar_paquetes, filter="udp port 53", store=0)
			writer.write(paquetes)
	except KeyboardInterrupt:
		writer.flush()
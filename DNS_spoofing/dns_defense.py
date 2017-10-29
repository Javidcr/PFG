#!/usr/bin/env python
# --*-- coding: UTF-8 --*--

__author__ = 'Francisco Javier del Castillo Ramírez'
__version__ = '1.0'
__last_modification__ = '2017.06.09'


#import logging
#import os
from scapy.all import *
#import sys
from collections import deque

cola = deque() #maxlen = 10
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
    print'\n============ {0} ============'.format('Analizando paquetes DNS')

def analizar_paquetes(paquete):

	#

    if paquete.haslayer(IP) and paquete.haslayer(UDP) and\
     paquete.haslayer(DNS) and paquete.haslayer(DNSRR):
     	cola.append(paquete)
        if len(cola)>0:
            for p_cola in cola:
				#print
				#print "[DNSRR].rdata: {0} -!- {1}".format(paquete[DNSRR].rdata, p_cola[DNSRR].rdata)
				#print "[IP].dst: {0} -=- {1}".format(paquete[IP].dst, p_cola[IP].dst)
				#print "[IP].sport: {0} -=- {1}".format(paquete[IP].sport, p_cola[IP].sport)
				#print "[IP].dport: {0} -=- {1}".format(paquete[IP].dport, p_cola[IP].dport)
				#print "[DNS].id: {0} -=- {1}".format(paquete[DNS].id, p_cola[DNS].id)
				#print "[DNS].qd.qname {0} -=- {1}".format(paquete[DNS].qd.qname, p_cola[DNS].qd.qname)
				#print "[IP].payload: {0} -!- {1}".format(paquete[DNS].payload, p_cola[DNS].payload)
				if p_cola[IP].dst == paquete[IP].dst and\
				p_cola[IP].sport == paquete[IP].sport and\
				p_cola[IP].dport == paquete[IP].dport and\
				p_cola[DNSRR].rdata != paquete[DNSRR].rdata and\
				p_cola[DNS].id == paquete[DNS].id and\
				p_cola[DNS].qd.qname == paquete[DNS].qd.qname and\
				p_cola[IP].payload != paquete[IP].payload:
					print "Se ha detectado un ataque de envenenmiento de DNS"
					print "TXID %s Request URL %s"%( p_cola[DNS].id, p_cola[DNS].qd.qname.rstrip('.'))
					print "Respuesta1 [%s]"%p_cola[DNSRR].rdata
					print "Respuesta2 [%s]"%paquete[DNSRR].rdata


if __name__ == '__main__':

	cabecera()
	try:

		while 1:
			paquetes = sniff(prn=analizar_paquetes, filter="udp port 53", store=0)
			writer.write(paquetes)
	except KeyboardInterrupt:
		writer.flush()
        #wireshark(paquetes)

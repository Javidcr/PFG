#!/usr/bin/env python
# --*-- coding: UTF-8 --*--

__author__ = 'Francisco Javier del Castillo Ramírez'
__version__ = '1.0'
__last_modification__ = '2017.06.08'

from scapy.all import *

paquetes = None
try:
    writer=PcapWriter("temp.pcap")
except:
    pass

def analizar_paquetes(paquete):
	pass
try:
	while 1:
		paquetes = sniff(prn=analizar_paquetes, filter="udp port 53") # filtrar UDP port 53
		writer.write(paquetes)
except KeyboardInterrupt:
	writer.flush()
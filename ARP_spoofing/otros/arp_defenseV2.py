#!/usr/bin/env python
# -*- coding: utf-8 -*-

import nmap
from scapy.all import ARP, sniff # import what you need


if __name__ == '__main__':
	
	datos_almacenados = dict() # don't need global
	while 1:
		def analizar(paquete):
			if ARP in paquete and paquete[ARP].op == 2: # make sure ARP is in the packet
				print "\nPaquete detectado: {}".format(paquete[ARP].psrc)
				print "Paquete detectado: {}".format(paquete[ARP].hwsrc)
				if paquete[ARP].psrc in datos_almacenados: #
					
					if datos_almacenados[paquete[ARP].psrc] != paquete[ARP].hwsrc:
						print "Paquete almacenado: {}".format(datos_almacenados)
						print("MAC del equipo atacante: {}".format(paquete[ARP].hwsrc))
						# Vendor list for MAC address
						mac = paquete[ARP].hwsrc
						nm = nmap.PortScanner()
						print "Buscando equipo atacante"
						nm.scan('192.168.1.0/24', arguments='-O')
						print "Escaneo terminado"
						for h in nm.all_hosts():
							if mac in nm[h]['addresses']:
								print(nm[h]['addresses'], nm[h]['vendor'])
						return "Hay un equipo atacando su PC, usando IP falsa: {}".format(paquete[ARP].psrc)
					
					else:
						return "Paquete ARP, no hay ataque detectado en este paquete..."
				else:
					datos_almacenados[paquete[ARP].psrc] = paquete[ARP].hwsrc
					return "Paquetes recibidos, no son paquetes ARP..."

		sniff(prn=analizar, filter="arp", timeout=10)

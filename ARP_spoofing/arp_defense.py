from scapy.all import ARP, sniff # import what you need

d = dict() # don't need global
while 1:
    def replay(pkt):
        if ARP in pkt and pkt[ARP].op == 2: # make sure ARP is in the packet
            if pkt[ARP].psrc in d: # just use in d
                if d[pkt[ARP].psrc] != pkt[ARP].hwsrc:
					print("\nMAC del equipo atacante: {}".format(pkt[ARP].hwsrc))
					return "\aHay un equipo atacando su PC, usando IP falsa: {}".format(pkt[ARP].psrc)
                else:
                    return "\nPaquete ARP recibido, no hay ataque detectado en este paquete..."
            else:
                d[pkt[ARP].psrc] = pkt[ARP].hwsrc
                return "\nPaquetes recibidos, no son paquetes ARP..."

    sniff(prn=replay, filter="arp", timeout=7.5)

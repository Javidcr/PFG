from scapy.all import *
import nmap

nm = nmap.PortScanner()
nm.scan()
for host in nm.all_hosts():
	print "\n[+]\tIP:", host
	print "\tSTATUS:", nm[host]['status']['state']
	try:
		print "\tMAC:", nm[host]['addresses']['mac']
	except:
		print "desconocida"


'''
while 1:
	packet = Ether()/ARP(op="who-has", hwsrc="", psrc="", pdst="192.168.1.1")
	send(packet)
'''
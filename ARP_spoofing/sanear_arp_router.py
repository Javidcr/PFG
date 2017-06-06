from scapy.all import *
import netifaces

addrs = netifaces.ifaddresses("wlp2s0")
try:
    mac = addrs[netifaces.AF_LINK][0]['addr']
    print mac 
    ip = addrs[netifaces.AF_INET][0]['addr']
    print ip
    while 1:
		packet = Ether()/ARP(op="who-has", hwsrc=mac, psrc=ip, pdst="192.168.1.1")
		send(packet)
except:
	print
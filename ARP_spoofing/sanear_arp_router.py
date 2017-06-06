from scapy.all import *
import netifaces
import nmap

'''
nm = nmap.PortScanner() # objeto donde se almacenan los equipos conectados a la red
nm.scan(hosts = '192.168.1.63')
nm.command_line()
nm.scaninfo()
for host in nm.all_hosts():
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())

for proto in nm[host].all_protocols():
        print('Protocol : %s' % proto)

lport = nm[host]['tcp'].keys()   #<------ This 'proto' was changed from the [proto] to the ['tcp'].
lport.sort()
for port in lport:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))


nma = nmap.PortScannerAsync()
def callback_result(host, scan_result):
	print '------------------'
	print host, scan_result

nma.scan(hosts='192.168.1.63', arguments='-sP', callback=callback_result)
while nma.still_scanning():
	print("Waiting >>>")
	nma.wait(2)
	nm = nmap.PortScannerYield()
for progressive_result in nm.scan('127.0.0.1/24'): print(progressive_result['hostnames'])

'''

# Enviar paquetes ARP para sanear la cache ARP del router

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

#Borramos todo iptables
iptables --flush
iptables --zero
iptables --delete-chain
iptables -F -t nat

#Borramos toda cache arp
ip -s -s neigh flush all
arp -d 192.168.1.1

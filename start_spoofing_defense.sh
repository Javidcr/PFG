#!/bin/bash
gnome-terminal -x bash -c "python ARP_spoofing/arp_defense.py" &
PID=$!
echo $PID | tee pid_arp

gnome-terminal -x bash -c "python IP_spoofing/ip_defense.py" &
PID=$!
echo $PID | tee pid_ip

exit 0

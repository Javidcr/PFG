#!/bin/bash

cd ARP_spoofing
gnome-terminal -x bash -c "python arp_defense.py" &
PID_ARP=$!
cd ..
echo -n 'Arrancado proceso arp_defense con PID = '
echo  $PID_ARP | tee pid_arp

#!/bin/bash
clear

DIA=`date +"%d/%m/%Y"`
HORA=`date +"%H:%M:%S"`

echo -e '\t[ '$DIA'  | '$HORA' ]\r'
echo -e '\n\tAutor: Francisco Javier del Castillo.\r'
echo -e '\n\tIniciando aplicacion para la defenda de ataques spoofing...'

echo -e '\n[#####                  ](33%)\r'

#Arranco IP defense
cd IP_spoofing
gnome-terminal -x bash -c "python ip_defense.py" &
PID_IP=$!
cd ..
echo -ne '\nArrancado proceso ip_defense con PID = '
echo  $PID_IP | tee pid_ip
#Fin Arranco IP defense

echo -e '\n[#############          ](66%)\r'

#Arranco ARP defense
cd ARP_spoofing
gnome-terminal -x bash -c "python arp_defense.py" &
PID_ARP=$!
cd ..
echo -ne '\nArrancado proceso arp_defense con PID = '
echo  $PID_ARP | tee pid_arp
#Fin Arranco ARP defense

echo -e '\n[#######################](100%)\r'
echo -e '\n'

exit 0

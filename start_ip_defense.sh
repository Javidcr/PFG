#!/bin/bash

cd IP_spoofing
gnome-terminal -x bash -c "python ip_defense.py" &
PID_IP=$!
cd ..
echo -n 'Arrancado proceso ip_defense con PID = '
echo  $PID_IP | tee pid_ip

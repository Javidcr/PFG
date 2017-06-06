#!/bin/bash
gnome-terminal -x bash -c "python sanear_arp_router.py" &
PID=$!
echo $PID | tee pid
exit 0

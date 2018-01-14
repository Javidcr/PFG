#!/bin/bash
clear

DIA=`date +"%d/%m/%Y"`
HORA=`date +"%H:%M:%S"`

echo -e '\t[ '$DIA'  | '$HORA' ]\r'
echo -e '\tIniciando aplicacion para la defenda de ataques spoofing...'

echo -e '[#####                  ](33%)\r'
./start_ip_defense.sh

echo -e '[#############          ](66%)\r'
./start_arp_defense.sh

echo -e '[#######################](100%)\r'
echo -e '\n'

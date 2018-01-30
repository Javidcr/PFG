#!/bin/bash
clear

DIA=`date +"%d/%m/%Y"`
HORA=`date +"%H:%M:%S"`

#echo -e '\t[ '$DIA'  | '$HORA' ]\r'
echo -e '\n\tAutor: Francisco Javier del Castillo.\r'
echo -e '\n\tInstalando dependencias de la aplicacion...'

apt-get update
apt-get install python python-nmap python-scapy
apt-get upgrade

exit 0

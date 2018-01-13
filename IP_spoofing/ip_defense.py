#!/usr/bin/env python
# --*-- coding: UTF-8 --*--


__author__ = 'Francisco Javier del Castillo Ramírez'
__version__ = '1.0'
__last_modification__ = '2017.06.09'

from scapy.all import *
#import tkMessageBox
#import commands
import os
import nmap
import time
import sys
from subprocess import Popen, PIPE
import commands
import re

diccionario = dict() # diccionario para almacenar IP y MAC de los pcs.
nm = nmap.PortScanner() # objeto donde se almacenan los equipos conectados a la red
nm.scan(hosts = '192.168.1.0/24', arguments = '-n -sP -PE -T5')
paquetes = None

try:
    pkts = PcapWriter("temp.pcap", append=True, sync=True)
    fecha_hora = time.strftime("%c")
except:
    pass


def cabecera():
    #Muestro la fecha y hora
    os.system('clear')
    localtime = time.asctime(time.localtime(time.time()))
    print'[ {0} ]'.format(localtime)

def analizar_red():
    print'\n============ {0} ============'.format('Analizando equipos de la red')
    for host in nm.all_hosts():

        if nm[host]['status']['state'] != "down":
            print
            print "\n[+]\tIP:", host
            print "\tSTATUS:", nm[host]['status']['state']
            try:
                print "\tMAC:", nm[host]['addresses']['mac']
            except:
                print "desconocida"
    print'\n============ {0} ============'.format('Analizando paquetes')

'''
def mostrar_resultado(resultado):
    #si no hay errores
    if resultado[0] == 0:
        print resultado[1]
    #si ahy errores
    else:
        print "Error: "+ str(resultado[0])
        print "Detalles: " + resultado[1]
'''
def __getRoute():

    """
    Funcion que devuelve el resultado del comando 'route -n'
    """
    try:
        return commands.getoutput("/sbin/route -n").splitlines()
    except:
        return ""

def returnGateway():

    """ Funcion que devuelve la puerta de enlace predeterminada ... """

    # Recorremos todas las lineas de la lista
    for line in __getRoute():
        # Si la primera posicion de la lista empieza 0.0.0.0
        if line.split()[0]=="0.0.0.0":
            # Cogemos la direccion si el formato concuerda con una direccion ip
            if re.match("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$", line.split()[1]):
                return line.split()[1]

    return ''

def pause():
    programPause = raw_input("Pulsa <ENTER> para continuar...")


def bloquear_pc(mac_atacante, ips_atacantes):

    try:

        print "\n\tBloqueando conexiones entrantes de la MAC {0} ...".format(mac_atacante)
        os.system('iptables -A INPUT -i wlp2s0 -m mac --mac-source '+ mac_atacante +' -j DROP')

        for ip_atacante in ips_atacantes:
            print "\tBloqueando conexiones entrantes de la IP {0} ...".format(ip_atacante)
            os.system('iptables -A INPUT -s '+ ip_atacante +' -j DROP')

            print "\tBloqueando conexiones salientes hacia la IP {0} ...".format(ip_atacante)
            os.system('iptables -A OUTPUT -s '+ ip_atacante +' -j DROP')

        print "\tBloqueando cualquier paquete TCP que no se ha iniciado con el Flag SYN activo..."
        os.system('iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP')

        print "\nSe han aplicado reglas para bloquear al atacante.\n"

        pause()
        #os.system("./start.sh")

    except:
        print "Error inesperado:", sys.exc_info()[0]
        print "Detalles:", sys.exc_info()[1]
        raise


def analizar_mac(mac_atacante):

    # array para obtener todas las ips correspondientes a la mac atacante
    ips_atacantes = list()
    try:
        fichero = open('LOG - '+fecha_hora+'.txt','w')
        fichero.write("\n\tHA SUFRIDO UN ATAQUE DE IP SPOOFING")
    except:
        pass

    for host in nm.all_hosts():

        if 'mac' in nm[host]['addresses']:
            if (nm[host]['addresses']['mac'] == mac_atacante.upper()):

                print "\n[+]\tDatos almacenados del atacante: "
                print  "\tIP:", host
                print "\tSTATUS:", nm[host]['status']['state']
                print "\tMAC:", nm[host]['addresses']['mac']

                fichero.write("\n\n[+]\tDatos almacenados del atacante: \n")
                fichero.write("\n\tIP:\t\t"+ host)
                fichero.write("\n\tSTATUS:\t"+ nm[host]['status']['state'])
                fichero.write("\n\tMAC:\t"+ nm[host]['addresses']['mac'])

                ips_atacantes.append(host)

    fichero.close()
    bloquear_pc(mac_atacante.upper(), ips_atacantes)


def enviar_paquete_router():

    # envio un paquete al router para que en su contestacion ( REPLY) almacene su IP y MAC reales.
    p_router = IP(dst=returnGateway())/ICMP()/"Esto es un paquete para el router"
    print "\n[+]\tEnviando paquete al router..."
    send(p_router)
    #p_router.show()

def es_paquete_router(pkt):

    ip_router = returnGateway()
    mac_router = None

    ip_pkt = pkt[IP].src
    mac_pkt = (pkt.src).upper()

    #obtengo la mac del router
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            if host == ip_router:
                mac_router = nm[host]['addresses']['mac']

    #print "IP Router:", format(ip_router), "\tMac Router:", format(mac_router)
    if ip_pkt == ip_router and mac_pkt == mac_router:
        return True

    elif ip_pkt != ip_router and mac_pkt == mac_router:
        return True

    elif ip_pkt != ip_router and mac_pkt != mac_router:
        return False


def es_ataque(ip_dicc, mac_dicc, ip_pkt, mac_pkt):

    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            if nm[host]['addresses']['mac'] == mac_pkt.upper() and nm[host]['addresses']['mac'] == mac_dicc.upper():
                if host != ip_dicc and ip_pkt == ip_dicc:
                    return True
                return False

def analizar_paquetes(pkt):

    pkts.write(pkt)
    enviar_paquete_router()

    # comprueba que es un paquete TCP
    if pkt.haslayer(TCP):
        '''
         se comprueba que la IP esta almacenada en el diccionario
         y no se trata de ningún paquete enviado por el router
         dado que estos paquetes vienen con la ip del router
         o de cualquier otro servidor al que se le ha hecho una petición
         y todos ellos vienen con la misma mac, la mac del router,
         por lo tanto el script detectaría que se está realizando un ataque
         al llegar varios paquetes con la misma mac y distintas ip.
         '''
        if (pkt[IP].src in diccionario) and es_paquete_router(pkt) == False:
            #pkt.show()
            #print "\n[+]\tMAC:", format(pkt.src)
            for key,val in diccionario.items():
                if val == pkt.src:
                    print "\n[+]\tMAC del diccionario: ", format(val)
                    print "\t[-] IP del diccionario: ",format(key), "\n\t[-] IP del paquete: ",format(pkt[IP].src)

                    if es_ataque(key, val, pkt[IP].src, pkt.src):
                        print '\n\n============ {0} ============'.format( 'ESTA SUFRIENDO UN ATAQUE DE IP SPOOFING')
                        analizar_mac(pkt.src)
                        return None

                    else:
                        return "Paquete TCP recibido, no hay ataque detectado en este paquete..."

        else:

            #almacena la ip y la mac del origen del paquete, el PC que envia el paquete
            diccionario[pkt[IP].src] = pkt.src
            print "\n[+]\tIP:", format(pkt[IP].src)
            return "Paquete recibido, IP y MAC almacenada en el diccionario..."


def parar_ejecucion():
    #os.system("./stop.sh")
    print "\n... Limpiando reglas iptables ..."
    os.system("iptables --flush")
    os.system("iptables --zero")
    os.system("iptables --delete-chain")
    os.system("iptables -F -t nat")
    print "\n... Limpiando cache ARP ..."
    os.system("ip -s -s neigh flush all")
    os.system("arp -d 192.168.1.1")
    print "\n... Guardando paquetes utilizados ..."
    pkts.flush()
    print "...\n"


if __name__ == '__main__':
    try:
        cabecera()
        analizar_red()
        while 1:
            sniff(prn=analizar_paquetes, filter="tcp port 80", store=0)

    except KeyboardInterrupt:
        parar_ejecucion()

    except:
        print "Error inesperado:", sys.exc_info()[0]
        print "Detalles:",sys.exc_info()[1]
        raise

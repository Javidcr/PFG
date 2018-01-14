#!/usr/bin/env python
# --*-- coding: UTF-8 --*--

#ESTE METODO FUNCIONA CUANDO SE ALAMACENA EN EL DICCIONARIO LA ip Y LA mac DEL ROUTER
#por ello lo primero que hago es enviar un paquete al router para poder almacenar su IP y MAC

__author__ = 'Francisco Javier del Castillo Ramírez'
__version__ = '1.0'
__last_modification__ = '2017.06.09'

from scapy.all import *
import os
import nmap
import time
import commands
#import sys
#from subprocess import Popen, PIPE

diccionario = dict() # diccionario para almacenar IP y MAC de los pcs.
nm = nmap.PortScanner() # objeto donde se almacenan los equipos conectados a la red
nm.scan(hosts = '192.168.1.0/24', arguments = '-n -sP -PE -T5')
# PID = int()
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
    print 'Defensa de ARP y DNS spoofing'

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

def pause():
    programPause = raw_input("Pulsa <ENTER> para continuar...")


def bloquear_pc(ip_atacante, mac_atacante, ip_router, mac_router):

    try:
        print "\n[+]\tSaneando cache ARP..."
        os.system("ip -s -s neigh flush all")
        os.system("arp -s "+ ip_router + " " + mac_router)
        print "\n[+]\tMostrando cache ARP"
        os.system("arp -a")

        print "\n\tBloqueando conexiones entrantes de la MAC {0} ...".format(mac_atacante)
        os.system('iptables -A INPUT -i wlp2s0 -m mac --mac-source '+ mac_atacante +' -j DROP')

        print "\tBloqueando conexiones entrantes de la IP {0} ...".format(ip_atacante)
        os.system('iptables -A INPUT -s '+ ip_atacante +' -j DROP')

        print "\tBloqueando conexiones salientes hacia la IP {0} ...".format(ip_atacante)
        os.system('iptables -A OUTPUT -s '+ ip_atacante +' -j DROP')

        print "\tBloqueando cualquier paquete TCP que no se ha iniciado con el Flag SYN activo..."
        os.system('iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP')

        print "\nSe ha saneado la cache ARP y se han aplicado reglas para bloquear al atacante.\n"

        pause()
        os.system("./start.sh")

    except:
        print "Error inesperado:", sys.exc_info()[0]
        print "Detalles:",sys.exc_info()[1]
        raise

def returnGateway():

    #Funcion que devuelve la puerta de enlace predeterminada
    result = ""
    try:
        result = commands.getoutput("/sbin/route -n").splitlines()
    except:
        raise

    # Recorremos todas las lineas de la lista
    for line in result:
        # Si la primera posicion de la lista empieza 0.0.0.0
        if line.split()[0]=="0.0.0.0":
            # Cogemos la direccion si el formato concuerda con una direccion ip
            if re.match("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$", line.split()[1]):
                return line.split()[1]

    return ''

def analizar_mac(mac_atacante):
    ip_atacante = ""
    ip_router = returnGateway()
    mac_router = ""

    try:
        fichero = open('LOG - '+fecha_hora+'.txt','w')
        fichero.write("\n\tHA SUFRIDO UN ATAQUE DE ARP SPOOFING")
    except:
        pass


    for host in nm.all_hosts():

        if 'mac' in nm[host]['addresses']:
            # print nm[host]
            # print "Comparando MAC atacante: {0} con MAC: {1}".format(mac_atacante, nm[host]['addresses']['mac'])
            if (nm[host]['addresses']['mac'] == mac_atacante):

                print "\n[+]\tDatos almacenados del atacante: "
                print "\tIP:", host
                print "\tSTATUS:", nm[host]['status']['state']
                print "\tMAC:", nm[host]['addresses']['mac']

                fichero.write("\n\n[+]\tDatos almacenados del atacante: \n")
                fichero.write("\n\tIP:\t\t"+ host)
                fichero.write("\n\tSTATUS:\t"+ nm[host]['status']['state'])
                fichero.write("\n\tMAC:\t"+ nm[host]['addresses']['mac'])

                ip_atacante = host

            elif(nm[host]['addresses']['ipv4'] == ip_router):
                mac_router = nm[host]['addresses']['mac']
    fichero.close()
    bloquear_pc(ip_atacante, mac_atacante, ip_router, mac_router)


def enviar_paquete_router():

    # envio un paquete al router para que en su contestacion ( REPLY) almacene su IP y MAC reales.
    p_router = IP(dst="192.168.1.1")/ICMP()/"Esto es un paquete para el router"
    print "\n[+]\tEnviando paquete al router..."
    send(p_router)
    #p_router.show()


def analizar_paquetes(pkt):
    pkts.write(pkt)
    enviar_paquete_router()

    # comprueba que es un paquete ARP de REQUEST o REPLY
    if ARP in pkt and pkt[ARP].op in (1,2):

        # se comprueba que la IP esta almacenada en el diccionario
        if pkt[ARP].psrc in diccionario:

            print "\n[+]\tIP:", format(pkt[ARP].psrc)
            print "\tMAC del diccionario:",format(diccionario[pkt[ARP].psrc]), "\n\tMAC del PC:         ",format(pkt[ARP].hwsrc)

            if diccionario[pkt[ARP].psrc] != pkt[ARP].hwsrc:
                print '\n\n============ {0} ============'.format( 'ESTA SUFRIENDO UN ATAQUE DE ARP SPOOFING')
                analizar_mac((pkt[ARP].hwsrc).upper())
                return None

            else:
                return "Paquete ARP recibido, no hay ataque detectado en este paquete..."

        else:

            #almacena la ip y la mac del origen del paquete, el PC que envia el paquete
            diccionario[pkt[ARP].psrc] = pkt[ARP].hwsrc
            print "\n[+]\tIP:", format(pkt[ARP].psrc)
            return "Paquete recibido, IP y MAC almacenada en el diccionario..."


def parar_ejecucion():
    os.system("./stop.sh")
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
            paquetes = sniff(prn=analizar_paquetes, filter="arp", store=0)

    except KeyboardInterrupt:
        parar_ejecucion()

    except:
        print "Error inesperado:", sys.exc_info()[0]
        print "Detalles:",sys.exc_info()[1]
        raise

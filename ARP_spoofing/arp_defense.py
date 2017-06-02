
# librerias
#ESTE METODO FUNCIONA CUANDO SE ALAMACENA EN EL DICCIONARIO LA ip Y LA mac DEL ROUTER

from scapy.all import ARP, sniff
import tkMessageBox
import commands
import os

diccionario = dict() # diccionario

def mostrar_resultado(resultado):
    #si no hay errores
    if resultado[0] == 0:
        print resultado[1]
    #si ahy errores
    else:
        print "Error: "+ str(resultado[0])
        print "Detalles: " + resultado[1]


def bloquear_mac(mac):
    print "\nBloqueando conexiones entrantes de la MAC {} ...".format(mac)
    resultado1 = commands.getstatusoutput('iptables -A INPUT -i wlp2s0 -m mac --mac-source '+ mac +' -j DROP')
    mostrar_resultado(resultado1)

    print "Bloqueando conexiones salientes hacia la MAC {} ...".format(mac)
    resultado2 = commands.getstatusoutput('iptables -A OUTPUT -i wlp2s0 -m mac --mac-source '+ mac +' -j DROP')
    mostrar_resultado(resultado2)


def analizar_paquetes(pkt):
    # comprueba que es un paquete ARP de REQUEST o REPLY
    if ARP in pkt and pkt[ARP].op in (1,2):

        # se comprueba que la IP esta almacenada en el diccionario
        if pkt[ARP].psrc in diccionario:

            print "\nIP:", format(pkt[ARP].psrc)
            print "MAC del diccionario:",format(diccionario[pkt[ARP].psrc]), "\nMAC del PC:         ",format(pkt[ARP].hwsrc)
            
            if diccionario[pkt[ARP].psrc] != pkt[ARP].hwsrc:
                print "--- ESTA SUFRIENDO UN ATAQUE DE ARP SPOOFING ---"
                mensaje = 'Su PC es victima de un ataque de ARP spoofing.\nMAC del PC: {}'.format(pkt[ARP].hwsrc)
                
                #mejorar el mensaje
                #tkMessageBox.showwarning('Aviso', mensaje)

                bloquear_mac(pkt[ARP].hwsrc)
                return "Hay un equipo usando IP falsa: {}".format(pkt[ARP].psrc)
            
            else:
                return "Paquete ARP recibido, no hay ataque detectado en este paquete..."
        
        else:

            #almacena la ip y la mac del origen del paquete, el PC que envia el paquete
            diccionario[pkt[ARP].psrc] = pkt[ARP].hwsrc
            print "\nIP:", format(pkt[ARP].psrc)
            return "Paquete recibido, IP y MAC almacenada en el diccionario..."


def parar_ejecucion():
    resultado3 = commands.getstatusoutput('iptables -F')
    mostrar_resultado(resultado3)
    print "..."


if __name__ == '__main__':
    try:
        while 1:
            sniff(prn=analizar_paquetes, filter="arp")

    except KeyboardInterrupt:
        parar_ejecucion()

    except:
        print "Error inesperado:", sys.exc_info()[0]
        raise

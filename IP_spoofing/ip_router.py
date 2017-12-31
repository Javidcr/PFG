#!/usr/bin/env python
# --*-- coding: UTF-8 --*--

import commands
import re



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

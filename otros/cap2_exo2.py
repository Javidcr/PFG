#!/usr/bin/python
#-*- coding: utf-8 -*-

import socket
print 'creaci�n de socket ...'
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
print 'socket creado'
print "conexi�n al host remoto"
s.connect(('www.ediciones-eni.com',80))
print 'conexi�n efectuada'
s.send( 'GET /index.html HTML/1.1\r\n\r\n')
data=s.recv(2048)
print data
s.close()

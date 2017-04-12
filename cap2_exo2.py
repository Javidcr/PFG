#!/usr/bin/python
#-*- coding: utf-8 -*-

import socket
print 'creación de socket ...'
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
print 'socket creado'
print "conexión al host remoto"
s.connect(('www.ediciones-eni.com',80))
print 'conexión efectuada'
s.send( 'GET /index.html HTML/1.1\r\n\r\n')
data=s.recv(2048)
print data
s.close()

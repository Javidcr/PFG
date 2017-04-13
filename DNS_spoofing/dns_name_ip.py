#!/usr/bin/env python
# --*-- coding: UTF-8 --*--
import sys, socket
try :
	result=socket.gethostbyaddr("8.8.8.8")
	print "El nombre del host primario es:"
	print " "+result[0]
	print "\nDirección:"
	for item in result[2]:
		print " "+item
except socket.herror,e:
	print "no se ha podido resolver:",e


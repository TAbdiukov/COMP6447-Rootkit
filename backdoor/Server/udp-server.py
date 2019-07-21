#/usr/bin/env/python3 
# https://serverfault.com/a/916132

# Python UDP Listener, listening on localhost 1025, change address 
# to listen on other ip/port combos. 
import socket

log = open("server.log", "a+")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 1025))
print("OK running")

while True:
	data, address = sock.recvfrom(65538)
	text = data.decode('ascii',  errors="replace")
	print('Connection from Client{} says,\n{}'.format(address, text))
	text = 'Your data was {} bytes long'.format(len(data))
	data = text.encode('ascii')
	sock.sendto(data, address)
	log.write(text+"\n")

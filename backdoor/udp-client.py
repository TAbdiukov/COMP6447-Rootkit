#python2
from pwn import *

io = pwnlib.tubes.remote.remote("192.168.20.19", 1025, typ='udp')
io.interactive()

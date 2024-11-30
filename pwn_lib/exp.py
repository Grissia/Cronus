from pwn import *
from pwn_lib.libs.cronus_shellcode import *
import sys
import time
FILENAME = "./chal"
context.log_level = "debug"
context.terminal = ["wt.exe", "wsl.exe"]
context.arch = "amd64"
exe = context.binary = ELF(FILENAME)
def one_gadget(filename: str) -> list:
    return [
        int(i) for i in __import__('subprocess').check_output(
            ['one_gadget', '--raw', filename]).decode().split(' ')
    ]
# brva x = b *(pie+x)
# set follow-fork-mode
# p/x $fs_base
# vis_heap_chucks
# set debug-file-directory /usr/src/glibc/glibc-2.35
# directory /usr/src/glibc/glibc-2.35/malloc
# handle SIGALRM ignore

"""
sc = asm(
    shellcraft.i386.linux.open(b'/home/chal/flag') +
    shellcraft.i386.linux.read('eax', 'esp', 50) +
    shellcraft.i386.linux.write('1', 'esp' ,50)
)

sc = cronus_shellcode_shell("i386", "execve", [address_of_bin_sh, 0, 0])
sc = cronus_shellcode_generate("amd64", "mprotect", [address_to_modify, length, permission(like 7 for rwx)])
"""

if len(sys.argv) == 1:
    r = process(FILENAME)
    if args.GDB:
        gdb.attach(r)
elif len(sys.argv) == 3:
    r = remote(sys.argv[1], sys.argv[2])
else:
    print("Usage: python3 {} [GDB | REMOTE_IP PORT]".format(sys.argv[0]))
    sys.exit(1)
s      = lambda data                :r.send(data)
sa     = lambda x, y                :r.sendafter(x, y)
sl     = lambda data                :r.sendline(data)
sla    = lambda x, y                :r.sendlineafter(x, y)
ru     = lambda delims, drop=True   :r.recvuntil(delims, drop)
rl     = lambda                     :r.recvline()
uu32   = lambda data, num           :u32(r.recvuntil(data)[-num:].ljust(4, b'\x00'))
uu64   = lambda data, num           :u64(r.recvuntil(data)[-num:].ljust(8, b'\x00'))
leak   = lambda name, addr          :log.success('{} = {}'.format(name, addr))
l32    = lambda                     :u32(r.recvuntil("\xf7")[-4:].ljust(4, b'\x00'))
l64    = lambda                     :u64(r.recvuntil("\x7f")[-6:].ljust(8, b'\x00'))
raw_input()
"""
comments here
"""



r.interactive()
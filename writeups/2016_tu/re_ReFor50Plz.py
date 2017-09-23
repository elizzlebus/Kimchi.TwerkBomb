############################################################################
# NOTES:
#       FUNCTION main
#       - Iterates through prog arg and xors each byte with 0x37
#       - Then compares this with the meow string
############################################################################

meow = "cbtcqLUBChERV[[Nh@_X^D]X_YPV[CJ"
xor = [0x37] * len(meow)

# print flag
print ''.join([chr(ord(p) ^ k) for p,k in zip(meow,xor)])

#!/usr/bin/env python
import base64

###############################################################################
# The provided file is an executable. It must have magic bytes and null bytes
# ... Since the title is xor, the key probably pops out a lot. 
# The magic bytes of Elf files ... it always starts with
# 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
###############################################################################

with open("crypto_xorbytes_hexxy", "r") as f:
  enc = f.read()

magic = [0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

def xor(A,B):
  key = ''
  for a,b in zip(A,B):
    x = ord(a) ^ b
    key += chr(x)
  return key

print("magic = ", ' '.join([hex(x) for x in magic]))
print("enc   = ", ' '.join([hex(ord(x)) for x in enc[:len(magic)]]))
key = xor(enc, magic)
print("key   = ", key)

# use magic bytes to get the key, xor file with key

data = ''
i = 0
for byte in enc:
  data += chr(ord(byte) ^ ord(key[i]))
  i = (i + 1) % len(key)

with open("crypto_xorbytes_decrypted", "wb") as f:
  f.write(data)

# flag can be seen by using strings/hexdump on decrypted file

#!/usr/bin/env python
import base64

###############################################################################
# Challenge:
# original data: "El Psy Congroo"
# encrypted data: "IFhiPhZNYi0KWiUcCls="
# encrypted flag: "I3gDKVh1Lh4EVyMDBFo="
###############################################################################

# NOTE: enc(data) is in base64 

data = "El Psy Congroo"
b64_enc_data = "IFhiPhZNYi0KWiUcCls="
enc_data = base64.b64decode(b64_enc_data)

# they should match
print("len(data) = " + str(len(data)))
print("len(enc_data) = " + str(len(enc_data)))

def xor(A,B):
  key = ''
  for a,b in zip(A,B):
    x = ord(a) ^ ord(b)
    key += chr(x)
  return key

key = xor(data, enc_data)
print("key = " + key)

b64_enc_flag = "I3gDKVh1Lh4EVyMDBFo="
enc_flag = base64.b64decode(b64_enc_flag)

flag = xor(key, enc_flag)
print("flag = " + flag)

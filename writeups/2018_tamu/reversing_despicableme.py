
###############################################################################
#
###############################################################################

cipher = "000101000000100111011001101110011101001110101111010001101111110000001001110010111011110111010001000100101011100010100010000001010100001111010010111110001110000111"

# This looks a lot like the encryption algorithm they used for crypto_simpledes
'''
lea     rax, [rbp+out_cipher]
mov     ecx, [rbp+rounds]
lea     rdx, [rbp+str_plaintext]
lea     rsi, [rbp+str_key]
mov     rdi, rax
call    encrypt(std::__cxx11::basic_string
'''

# Even the sboxes are the same...
'''
.text:00000000000016EE mov     [rbp+var_A0], 5
.text:00000000000016F8 mov     [rbp+var_9C], 2
.text:0000000000001702 mov     [rbp+var_98], 1
.text:000000000000170C mov     [rbp+var_94], 6
.text:0000000000001716 mov     [rbp+var_90], 3
.text:0000000000001720 mov     [rbp+var_8C], 4
.text:000000000000172A mov     [rbp+var_88], 7
.text:0000000000001734 mov     [rbp+var_84], 0
.text:000000000000173E mov     [rbp+var_80], 1
.text:0000000000001745 mov     [rbp+var_7C], 4
.text:000000000000174C mov     [rbp+var_78], 6
.text:0000000000001753 mov     [rbp+var_74], 2
.text:000000000000175A mov     [rbp+var_70], 0
.text:0000000000001761 mov     [rbp+var_6C], 7
.text:0000000000001768 mov     [rbp+var_68], 5
.text:000000000000176F mov     [rbp+var_64], 3
.text:0000000000001776 mov     [rbp+var_60], 4
.text:000000000000177D mov     [rbp+var_5C], 0
.text:0000000000001784 mov     [rbp+var_58], 6
.text:000000000000178B mov     [rbp+var_54], 5
.text:0000000000001792 mov     [rbp+var_50], 7
.text:0000000000001799 mov     [rbp+var_4C], 1
.text:00000000000017A0 mov     [rbp+var_48], 3
.text:00000000000017A7 mov     [rbp+var_44], 2
.text:00000000000017AE mov     [rbp+var_40], 5
.text:00000000000017B5 mov     [rbp+var_3C], 3
.text:00000000000017BC mov     [rbp+var_38], 0
.text:00000000000017C3 mov     [rbp+var_34], 7
.text:00000000000017CA mov     [rbp+var_30], 6
.text:00000000000017D1 mov     [rbp+var_2C], 2
.text:00000000000017D8 mov     [rbp+var_28], 1
.text:00000000000017DF mov     [rbp+var_24], 4
'''

S1 = ['101','010','001','110','011','100','111','000','001','100','110','010','000','111','101','011']
S2 = ['100','000','110','101','111','001','011','010','101','011','000','111','110','010','001','100']

# The default are the same input for crypto_simpledes but it's not producing
# the same cipher or decrypting the same way ...
'''
$ ./larrycrypt.dms --help
Usage: larrycrypt [Option] <value> ...
Options:
	-R <rounds>, --rounds <rounds>: Set R, default 2
	-K <key>, --key <key>: Set key, default "Mu"
	-m <message>, --message <message>: Set message, default "MiN0n!"
'''

# psuedo code
'''
encrypt(out_cipher, key, plaintext, rounds)
  -> getKeybits
  -> doRounds
        -> expand
        -> sBox
        -> doRounds
  -> 6bit_tostring
'''

# It uses a c++ bitset class of length 12, 8, 6
'''
bitset<12ul>
bitset<8ul>
bitset<6ul>
'''

import binascii
# the expand function is the same based on the indices that get moved
# (looking at the order of single digit number that gets moved as indices)
# 0 -> 0; 1 -> 1; 3 -> 2; 2 -> 3; 3 -> 4; 2 -> 5; 4 -> 6; 5 -> 7 
def expand(Rr):
  assert(len(Rr) == 6)
  return Rr[0:2] + Rr[3] + Rr[2:4] + Rr[2] + Rr[4:6]

# the other helper functions are also the same
def unexpand(Rr):
  assert(len(Rr) == 8)
  return Rr[0:2] + Rr[3:5] + Rr[6:8]

def sboxes(s1, s2):
  s1 = int(s1,2)
  s2 = int(s2,2)
  return S1[s1] + S2[s2]

def xor(aRr, Lr):
  y = int(aRr, 2) ^ int(Lr,2)
  return bin(y)[2:].zfill(len(aRr))

def ascii2bin(s):
  b = ''
  for char in s:
    b += bin(ord(char))[2:].zfill(8)
  return b

def bin2ascii(b):
  b = b[:len(b)/8*8]
  n = int(b,2)
  s = '%x' % n 
  # make sure hex string is even length
  if len(s) % 2 != 0:
    s = '0' + s
  return binascii.unhexlify(s)


def alterRr(Rr,key, i,R,r):
  eRr = expand(Rr)
  xRr = xor(eRr, getroundkey(key, i*R + r))
  s1 = xRr[:4]
  s2 = xRr[4:]
  return sboxes(s1,s2)

def getroundkey(key, starti):
  key = key * (starti/len(key) + 2)
  return key[starti:starti+8]


# Instead of encrypting in chunks (ECB mode), there is a chaining effect
# where the last encryption block affects the next
def encrypt(pt, key, R):
  cipher = ''
  N = len(pt)/6
  Lp = pt[:6]

  for i in range(1,N):
    Rp = pt[i*6:i*6+6]

    for r in range(R):
      Lr = Rp
      aRp = alterRr(Rp, key, i-1, R, r)
      Rr = Rp = xor(aRp, Lp)
      Lp = Lr
    Lp = Rr
    # cipher += Lr # If you want to print out the cipher
    cipher = Lr # Used as part of the decryption method
  return cipher

def decrypt(cipher, key, R):
  pt = ''
  N = len(cipher)/6

  guesses = []

  # guess initial 12 bit of plaintext
  ci = cipher[:6]
  for pt_guess in range(0, 0b111111111111):
    ptb = '{0:012b}'.format(pt_guess)
    Lr = encrypt(ptb, key, R)
    if Lr == ci:
      guesses.append(ptb)

  # Use recursion to guess the rest of the plaintext, 6bits at a time
  for pt_guess in guesses:
    pt_guesses = guess_chain(pt_guess, cipher[6:], key, R)
    if pt_guesses:
      for pt in pt_guesses:
        print bin2ascii(pt), pt

def guess_chain(pt, cipher, key, R):
  guesses = guess_next_block(pt, cipher, key, R)
  guesses = [pt + guess for guess in guesses]
  if len(guesses) == 0: # chain ends here, no more guesses to try
    return None
  elif len(cipher) == 6: # multiple guesses complete this cipher
    return guesses
  else:
    cipher = cipher[6:]
    all_guesses = []

    # for each possible pt, try to complete the rest of the cipher chain
    for pt in guesses:
      chained_guesses = guess_chain(pt, cipher, key, R)
      if chained_guesses:
        all_guesses.extend(chained_guesses)
    return all_guesses

def guess_next_block(pt, ci, key, R):
  guessesi = []
  # Using the next cipher block as what we want to encrypt to, find the
  # plaintext that produces that cipher block
  for pt_guess in range(0, 0b111111):
    ptb = '{0:06b}'.format(pt_guess)
    Lr = encrypt(pt + ptb, key, R)
    if ci[:6] == Lr:
      guessesi.append(ptb)
  return guessesi

if __name__=="__main__":
  cipher = "000101000000100111011001101110011101001110101111010001101111110000001001110010111011110111010001000100101011100010100010000001010100001111010010111110001110000111"

  # The key also never changes even if you set the parameter to the larrycrypt
  # program
  # key = "V3c70R"
  key = "Mu"
  
  R = 4
  
  decrypt(cipher, ascii2bin("Mu"), 4)  

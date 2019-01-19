#!/usr/bin/python3

###############################################################################
# this program uses Py-Enigma python3 library
# It must be run with python3 and have the library installed.
# > virtualenv -p /usr/bin/python3 py3env
# > source py3env/bin/activate
# > pip install package-name
# > pip install py-enigma
# Reference: https://bitbucket.org/bgneal/enigma/
#
# to run this program:
# python3 crypto_enigmatoofar.py
###############################################################################

from enigma.machine import EnigmaMachine

'''
ciphertext = "IPUXZGICZWASMJFGLFVIHCAYEGT" # Crib
for i in range(1,26):
  for j in range(1,26):
    for k in range(1,26):
      rings = [i,j,k]

      machine = EnigmaMachine.from_key_sheet(
        rotors='I II III', # Given
        reflector='B',
        ring_settings=rings, # Guessing
        plugboard_settings='AV BS CG DL FU HZ IN KM OW RX') # Given


      plaintext = machine.process_text(ciphertext)
      if 'HOWDY' in plaintext:
        print(plaintext)
        print(rings)
'''

###############################################################################
# OUTPUT:
# HOWDYAGGIESTHEWEATHEUISFINE
# [19, 2, 14]
###############################################################################

machine = EnigmaMachine.from_key_sheet(
            rotors='I II III',
            reflector='B',
            ring_settings=[19, 2, 14],
            plugboard_settings='AV BS CG DL FU HZ IN KM OW RX')

plaintext = machine.process_text("LTHCHHBUZODFLJOAFNNAEONXPLDJQVJCZPGAVOLN")
print(plaintext)

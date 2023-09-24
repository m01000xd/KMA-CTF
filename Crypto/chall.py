import string
from hashlib import md5
import random

def encode(m):
    return ''.join(bin(ord(c))[2:] for c in m)

flag = "KMA{" + "".join(random.choices(string.printable[:-6], k=27)) + "}"
#print(f'{flag = }')

flag_hash = md5(flag.encode()).hexdigest()
print(f'{flag_hash = }')

flag_encode = encode(flag)
print(f'{flag_encode = }')

'''
flag_hash = '16ab78b0c0654e663d7e2e22ac0a9b7a'
flag_encode = '10010111001101100000111110111010001011000111000101010110110001101101001011100101110000111010110101111000101111001111110100000010001111000111011011011110101011111110011000111110111101001001000100011010001101111101'
'''
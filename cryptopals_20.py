#!/usr/bin/env python

from base64 import b64decode
from os import urandom

from cryptopals_10 import xor
from cryptopals_18 import aes_ctr
from cryptopals_19 import guess_aes_ctr_keystream


if __name__ == '__main__':
    print('Challenge #20 - Break fixed-nonce CTR statistically')

    nonce = 0
    key = urandom(16)

    ciphertexts = []
    with open('data/20.txt', 'rb') as f:
        for line in f:
            ciphertexts.append(aes_ctr(key, nonce, b64decode(line)))

    guessed_keystream = guess_aes_ctr_keystream(ciphertexts)
    print(guessed_keystream)
    for ct in ciphertexts:
        print(xor(guessed_keystream, ct))

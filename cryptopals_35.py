#!/usr/bin/env python

import os

from cryptopals_15 import pkcs7_strip
from cryptopals_10 import cbc_encrypt, cbc_decrypt
from cryptopals_33 import dh_key, modpow
from cryptopals_34 import Echo, dh_digest


if __name__ == '__main__':
    print('Challenge #35 - Implement DH with negotiated groups, and break with malicious "g" parameter')

    p = 3456
    g = 7

    # Generate a public key for A
    A, a = dh_key(p, g)

    # A = (g ** a) % p
    # s = (A ** b) % p  (or B ** a...)

    # Attacks
    # 1. g = 1 implies s = 1
    # 2. g = p implies s = 0
    # 3. g = p - 1 implies
    #     s = 1 if a or b are odd
    #     s = p - 1 if both are even

    # Attack #1 - g = 1
    plaintext = b'more top secret for your eyes only info??'

    # for the first attack, a middleman changes g = 1 during setup
    # (and A, as A is based on g)
    echo = Echo(p, 1, 1)

    # now when we encrypt our ciphertext and send it to the "bot"
    key = dh_digest(modpow(echo.B, a, p))
    iv = os.urandom(16)
    ciphertext = cbc_encrypt(plaintext, key, iv)
    resp_ciphertext, resp_iv = echo.recieve(ciphertext, iv) 

    # the middleman should be able to decrypt the ciphertext as s = 1 as it's
    # returned
    key = dh_digest(1)
    mitm_plaintext = pkcs7_strip(cbc_decrypt(resp_ciphertext, key, resp_iv))
    assert plaintext == mitm_plaintext

    # Attack #2 - g = p
    plaintext = b'do not open'

    # middleman changes g = p during setup
    # (setting A to p in the process)
    echo = Echo(p, p, p)

    # now when we encrypt our ciphertext and send it to the "bot"
    key = dh_digest(modpow(echo.B, a, p))
    iv = os.urandom(16)
    ciphertext = cbc_encrypt(plaintext, key, iv)
    resp_ciphertext, resp_iv = echo.recieve(ciphertext, iv) 

    # the middleman should be able to decrypt the ciphertext as s = 1 as it's
    # returned
    key = dh_digest(0)
    mitm_plaintext = pkcs7_strip(cbc_decrypt(resp_ciphertext, key, resp_iv))
    assert plaintext == mitm_plaintext

    # Attack #3 - g = p - 1
    plaintext = b'mystery'

    # middleman changes g = p - 1 during setup
    # (setting A to 1 in the process)
    echo = Echo(p, p - 1, 1)

    # now when we encrypt our ciphertext and send it to the "bot"
    key = dh_digest(modpow(1, a, p))
    iv = os.urandom(16)
    ciphertext = cbc_encrypt(plaintext, key, iv)
    resp_ciphertext, resp_iv = echo.recieve(ciphertext, iv) 

    # The key used with either be 1, or A, depending on what 'b' is randomized
    # to be, so if we set 'A' to 1, either case works out the same :)
    # This might be a little bit cheap...
    key = dh_digest(1)
    mitm_plaintext = pkcs7_strip(cbc_decrypt(resp_ciphertext, key, resp_iv))
    assert plaintext == mitm_plaintext

    # From here the middleman could re-encrypt with the original, trapped 'A'
    # public key

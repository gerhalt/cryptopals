#!/usr/bin/env python
from base64 import b64decode
from decimal import Decimal

from cryptopals_33 import modpow
from cryptopals_39 import RSA


TEST_STRING = b64decode(b"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")


def is_plaintext_even(rsa: RSA, ciphertext: int) -> bool:
    """Given a private key and an RSA ciphertext, returns whether the last bit
    is odd or even.
    """
    plaintext = rsa.decrypt(ciphertext)
    return plaintext % 2 == 0


if __name__ == '__main__':
    print('Challenge #46 - RSA parity oracle')

    rsa = RSA()

    ciphertext = rsa.encrypt(int.from_bytes(TEST_STRING, 'big'))

    assert is_plaintext_even(rsa, ciphertext) == False

    lower_bound = 0
    upper_bound = rsa.n
    while upper_bound >= lower_bound:
        #print(upper_bound, lower_bound)
        print(str(int(upper_bound).to_bytes(256, 'big')))

        # Shift the plaintext over by a bit, mod n
        ciphertext = ciphertext * modpow(2, rsa.e, rsa.n)
        new_bound = (upper_bound + lower_bound) // 2

        if is_plaintext_even(rsa, ciphertext):
            # If, after doubling the plaintext, the last bit is still even, it
            # indicates the modulus wasn't wrapped (n is prime!) and therefore
            # the plaintext is less than half the modulus
            upper_bound = new_bound
        else:
            lower_bound = new_bound

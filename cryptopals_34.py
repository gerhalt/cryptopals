#!/usr/bin/env python

import os
from math import ceil

from cryptopals_10 import cbc_encrypt, cbc_decrypt
from cryptopals_15 import pkcs7_strip
from cryptopals_28 import sha1
from cryptopals_33 import dh_key, modpow


def dh_digest(key: int) -> bytes:
    """Convert a Diffie-Hellman public key into an 128-bit digest.
    """
    return sha1(key.to_bytes(ceil(len(bin(key)) / 8), 'big'))[:16] 


class Echo(object):

    def __init__(self, p: int, g: int, A: int):
        self.p = p
        self.g = g
        self.A = A

        # Generate B
        self.B, self.b = dh_key(p, g)

    def recieve(self, msg: bytes, iv: bytes) -> bytes:
        """Recieves a message, decrypts it with A's key, and then re-encrypts
        with a new IV and returns

        Returns:
            (bytes, bytes): msg, iv tuple
        """
        s = modpow(self.A, self.b, self.p)
        k = dh_digest(s)

        plaintext = pkcs7_strip(cbc_decrypt(msg, k, iv))

        iv = os.urandom(16)
        return cbc_encrypt(plaintext, k, iv), iv


class Middleman(object):

    def __init__(self, p: int, g: int, A: int):
        self.p = p
        self.g = g
        self.A = None

        self.echo = Echo(p, g, p)

    @property
    def B(self):
        # With B replaced with p, s = (p ^ anything > 0) % p = 0
        return self.p

    def recieve(self, msg: bytes, iv: bytes) -> bytes:
        # Relay to B
        ciphertext, iv = self.echo.recieve(msg, iv)

        k = dh_digest(0)
        print('MITM:', pkcs7_strip(cbc_decrypt(ciphertext, k, iv)))

        return ciphertext, iv


if __name__ == '__main__':
    print('Challenge #34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection')

    p = 12345
    g = 5

    A, a = dh_key(p, g)
    echo = Echo(p, g, A)

    # Test basic echo
    plaintext = b'some plaintext'

    key = dh_digest(modpow(echo.B, a, p))
    iv = os.urandom(16)
    ciphertext = cbc_encrypt(plaintext, key, iv) 
    resp_ciphertext, resp_iv = echo.recieve(ciphertext, iv)

    # The sent and recieved plaintexts should be identical, after padding is
    # stripped away
    resp_plaintext = pkcs7_strip(cbc_decrypt(resp_ciphertext, key, resp_iv))
    assert plaintext == resp_plaintext

    # MITM
    mitm = Middleman(p, g, A)

    plaintext = b'top secret, do not read'
    key = dh_digest(modpow(mitm.B, a, p))
    iv = os.urandom(16)
    ciphertext = cbc_encrypt(plaintext, key, iv) 
    resp_ciphertext, resp_iv = mitm.recieve(ciphertext, iv)

    # From A's perspective, responses should still be decryptable
    resp_plaintext = pkcs7_strip(cbc_decrypt(resp_ciphertext, key, resp_iv))
    assert plaintext == resp_plaintext

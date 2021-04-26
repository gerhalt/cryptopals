#!/usr/bin/env python

import json
from calendar import timegm
from datetime import datetime, timezone
from hashlib import sha256
from random import randint
from typing import Tuple

from cryptopals_33 import modpow
from cryptopals_39 import modinv, RSA


class RSAServer(object):

    def __init__(self):
        self.rsa = RSA()

        # For storing hashes of messages we've already seen
        self.seen = set()

    @property
    def public_key(self) -> Tuple[int, int]:
        """Server's public key, as (exponent, modulo)"""
        return self.rsa.e, self.rsa.n 
    
    def decrypt(self, ciphertext: int) -> int:
        """Decrypts and returns the corresponding plaintext to the input
        ciphertext. If `ciphertext` has been submitted already, throws a
        `ValueError`.
        """
        plaintext = self.rsa.decrypt(ciphertext)
        print(plaintext.to_bytes(128, 'big'))

        """
        msg_digest = sha256(plaintext).digest()
        if msg_digest not in self.seen:
            self.seen.add(msg_digest)
            return plaintext
        else:
            raise ValueError('Ciphertext already seen')
        """
        return plaintext


if __name__ == '__main__':
    print('Challenge #41 - Implement unpadded message recovery oracle')

    server = RSAServer()

    # With a generated, good plaintext
    plaintext = int.from_bytes(bytes(json.dumps({
        'time': timegm(datetime.now(tz=timezone.utc).timetuple()),
        'social': '555-55-5555'
    }).encode('UTF-8')), 'big')

    e, n = server.public_key
    c = modpow(plaintext, e, n)

    s = randint(2, 1000)
    c_prime = (modpow(s, e, n) * c) % n

    p_prime = server.decrypt(c_prime)

    recovered_p = p_prime * modinv(s, n)

    print(plaintext)
    print(recovered_p)

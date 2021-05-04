#!/usr/bin/env python
from typing import Tuple

from Crypto.Util import number

from cryptopals_33 import modpow


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended greatest common denominator.

    Taken from:
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a: int, m: int) -> int:
    """Calculates the modular multiplicative inverse of a number `a` against
    mod `m`.

    Equivalent in Python 3.8+: `y = pow(x, -1, m)`
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m


def moddiv(a: int, b: int, m: int) -> int:
    """Divides a over b under modulo m.
    """
    a = a % m
    return (modinv(b, m) * a) % m


class RSA(object):

    def __init__(self): 
        prime_bits = 1024
        while True:
            p = number.getPrime(prime_bits)
            q = number.getPrime(prime_bits)

            n = p * q               # our modulo
            et = (p - 1) * (q - 1)  # "totient"
            e = 3

            try:
                d = modinv(e, et)
                break
            except:
                pass

        self.p = p
        self.q = q
        self.n = n
        self.e = e
        self.d = d
       
    def encrypt(self, plaintext: int) -> int:
        return modpow(plaintext, self.e, self.n)
    
    def decrypt(self, ciphertext: int) -> int:
        return modpow(ciphertext, self.d, self.n)
    

if __name__ == '__main__':
    print('Challenge #39 - Implement RSA')

    # Public key is (e, n)
    # Private key is (d, n)

    rsa = RSA()
    print(f'P: {rsa.p}')
    print(f'Q: {rsa.q}')

    # Encryption
    inp = 45
    c = rsa.encrypt(inp)

    # Decryption
    out = rsa.decrypt(c)

    assert out == inp

    # Silly, larger string
    inp = b'a test string'
    c = rsa.encrypt(int.from_bytes(inp, 'big'))

    out = rsa.decrypt(c).to_bytes(len(inp), 'big')
    assert inp == out 

    # NOTE: `n` must be less than the numeric input value for this to work
    inp = rsa.n
    c = rsa.encrypt(inp)
    out = rsa.decrypt(c)

    assert inp != out

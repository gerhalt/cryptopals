#!/usr/bin/env python

from cryptopals_39 import modinv
from cryptopals_43 import DSA


if __name__ == '__main__':
    print('Challenge #45 - DSA parameter tampering')

    # When we sign a message with g=0
    dsa = DSA(g=0)
    msg = b'The oldest and strongest emotion of mankind is fear, and the oldest and strongest kind of fear is fear of the unknown'

    # Infinitely loops, because 0 to any positive power is 0 (r = ), failing the
    # non-zero requirements for r and s
    # r, s = dsa.sign(msg)

    # Try g=p+1
    dsa = DSA(g=DSA.DEFAULT_P + 1)

    r1, s1 = dsa.sign(b'Hello, world')
    r2, s2 = dsa.sign(b'Goodbye, world')

    # Build magic signature
    z = 14
    r = (dsa.y ** 12 % dsa.p) % dsa.q
    s = (r * modinv(z, dsa.q)) % dsa.q

    assert dsa.verify(b'Hello, world', r, s)
    assert dsa.verify(b'Goodbye, world', r, s)

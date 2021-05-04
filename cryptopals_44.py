#!/usr/bin/env python

from collections import defaultdict

from cryptopals_28 import sha1
from cryptopals_39 import moddiv, modinv
from cryptopals_43 import DSA, dsa_recover_x


if __name__ == '__main__':
    print('Challenge #44 - DSA nonce recovery from repeated nonce')
    
    dsa = DSA()

    y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
    private_key_sha1 = 0xca8f6f7c66fa362d40760d135b763eb8527d3d52

    msg = s = r = m = None
    ks = defaultdict(list)
    for i, line in enumerate(open('data/44.txt', 'r')):
        key, value = line.split(': ')

        if key == 'msg':
            msg = value
        elif key == 's':
            s = int(value)
        elif key == 'r':
            r = int(value)
        elif key == 'm':
            m = int(value, 16)

        if i % 4 == 3:
            signature = (msg, s, r, m)
            assert all(signature)

            # r will be the same for messages signed using the same k
            ks[r].append(signature) 

            msg = s = r = m = None

    for signatures in ks.values():
        # Need multiple messages signed using the same k
        if len(signatures) == 1:
            continue
        
        msg1, s1, r1, m1 = signatures[0]
        msg2, s2, r2, m2 = signatures[1]

        # Convert to bytes for consistency
        msg1 = bytes(msg1.encode('UTF-8'))
        msg2 = bytes(msg2.encode('UTF-8'))

        # TODO: Unable to determine the modular multiplicative inverse for two
        #       of these pairs of messages, need to look into this
        try:
            k = (((m1 - m2) % dsa.q) * modinv(s1 - s2, dsa.q)) % dsa.q
        except Exception as e:
            print(e)
            continue

        print(f'K: {k}')

        # Now, back to #43, can determine x from k
        x = dsa_recover_x(msg1, k, dsa.q, r1, s1)
        print(f'X: {x}')

        # When we sign a message again, using the x and k we found, the (r, s)
        # signature should be identical
        dsa = DSA(x=x, y=y)
        test_r1, test_s1 = dsa.sign(msg1, k=k)

        assert test_r1 == r1
        assert test_s1 == s1

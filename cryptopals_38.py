#!/usr/bin/env python
"""

More details on http://srp.stanford.edu/ndss.html#secactivedict
In particular, the "Computation of B" section describes why using
B = g ^ b is insufficient to prevent active attacks.
"""
import os
import string
from hashlib import sha256
from random import choice, randint

from cryptopals_33 import dh_key, modpow, REAL_P as N

g = 2
k = 3

# Dictionary of words that could be used as passwords
with open('data/38.txt', 'r') as f:
    words = [w for w in f.read().split('\n')]


def salted_sha256(K, salt):
    return sha256((str(K) + str(salt)).encode('UTF-8')).digest()


class SimpleSRPClient(object):

    def __init__(self, I, P):
        self.I = I
        self.P = P

        self.A, self._a = dh_key(N, g)

    def recieve_keys(self, salt, B, u):
        self.salt = salt
        self.B = B
        self.u = u

        xH = sha256((str(self.salt) + self.P).encode('UTF-8')).digest()
        self.x = int.from_bytes(xH, byteorder='big') 

        self.S = modpow(self.B, self._a + self.u * self.x, N)
        self.K = sha256(str(self.S).encode('UTF-8')).digest()


class SimpleSRPServer(object):

    def __init__(self, P):
        self.salt = randint(1, 10000)
        self.P = P

        xH = sha256((str(self.salt) + self.P).encode('UTF-8')).digest()
        self.x = int.from_bytes(xH, byteorder='big') 
        self.v = modpow(g, self.x, N)

    def exchange_keys(self, I, A):
        self.I = I
        self.A = A

        self.u = int.from_bytes(os.urandom(16), byteorder='big')
        self.B, self._b = dh_key(N, g)

        self.S = modpow(self.A * modpow(self.v, self.u, N), self._b, N)
        self.K = sha256(str(self.S).encode('UTF-8')).digest()

        return self.salt, self.B, self.u
    
    def login(self, K):
        return self.K == K


class MITMServer(object):

    def exchange_keys(self, server, I, A):
        self.I = I
        self.A = A

        self.salt, _B, self.u = server.exchange_keys(I, A)

        # Generate and force a new public key
        self.B, self._b = dh_key(N, g)

        return self.salt, self.B, self.u

    def brute_force(self, salted_K):
        """Given a passed client `K`, attempts to brute force the password.
        """
        for trial_pw in words:
            xH = sha256((str(self.salt) + trial_pw).encode('UTF-8')).digest()
            x = int.from_bytes(xH, byteorder='big') 
            v = modpow(g, x, N)
            S = modpow(self.A * modpow(v, self.u, N), self._b, N) 
            test_K = sha256(str(S).encode('UTF-8')).digest()

            salted_test_K = salted_sha256(test_K, self.salt) 

            if salted_test_K == salted_K:
                print(f'Password is {trial_pw}')
                break
        else:
            print('Password not found')


if __name__ == '__main__':
    print('Challenge #38 - Offline dictionary attack on simplified SRP')

    # Ensure the protocol works with a valid password
    I = 'email@test.com'
    P = choice(words)
    client = SimpleSRPClient(I, P)
    server = SimpleSRPServer(P)
    
    salt, B, u = server.exchange_keys(I, client.A)
    client.recieve_keys(salt, B, u)
    
    assert server.login(client.K), 'Simple SRP should work with a valid password'

    # Now run the protocol as a MITM attacker; pose as the server and use
    # arbitrary values for b, B, u and salt. Crack the password from A's
    # HMAC-SHA256(K, salt)
    mitm = MITMServer()
    salt, B, u = mitm.exchange_keys(server, I, client.A)
    client.recieve_keys(salt, B, u)

    salted_K = salted_sha256(client.K, salt)
    mitm.brute_force(salted_K)

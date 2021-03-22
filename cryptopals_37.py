#!/usr/bin/env python
from hashlib import sha256
from random import randint

from cryptopals_33 import dh_key, modpow, REAL_P as N

g = 2
k = 3


class Client(object):

    def __init__(self, I, P):
        self.I = I
        self.P = P

        self.A, self._a = dh_key(N, g)
    
    def recieve_key(self, salt, B):
        self.salt = salt
        self.B = B

        uH = sha256(str(self.A | self.B).encode('UTF-8')).digest()
        self.u = int.from_bytes(uH, byteorder='big')

        xH = sha256((str(salt) + self.P).encode('UTF-8')).digest()
        self.x = int.from_bytes(xH, byteorder='big') 

        self.S = modpow(self.B - k * modpow(g, self.x, N), self._a + self.u * self.x, N)
        self.K = sha256(str(self.S).encode('UTF-8')).digest()


class Server(object):

    def __init__(self, P):
        self.P = P
        self.salt = randint(1, 1000)

        server_xH = sha256((str(self.salt) + self.P).encode('UTF-8')).digest()
        self.x = int.from_bytes(server_xH, byteorder='big') 

        self.v = modpow(g, self.x, N)

    def exchange_keys(self, I, A):
        """Accepts a client `I` (email) and `A` (public key) and returns our
        randomized salt and server public key `B`.
        """
        self.A = A
        self.B, self._b = dh_key(N, g)
        self.B += k * self.v

        uH = sha256(str(self.A | self.B).encode('UTF-8')).digest()
        self.u = int.from_bytes(uH, byteorder='big')

        self.S = modpow(A * modpow(self.v, self.u, N), self._b, N)
        self.K = sha256(str(self.S).encode('UTF-8')).digest()

        return self.salt, self.B 
    
    def login(self, K):
        """Given a key `K`, returns a flag indicating whether or not it
        is the same as the `K` calculated on the server.
        """
        return self.K == K


if __name__ == '__main__':
    print('Challenge #37 - Break SRP with a zero key')

    # Client(I, P)
    I = 'anemail@emailer.com'
    P = 'as3c\/r3passes'
    client = Client(I, P)
    server = Server(P)

    salt, B = server.exchange_keys(I, client.A)
    client.recieve_key(salt, B)

    # Login should be accepted with a correct password digest
    assert server.login(client.K), 'Correct key digest should be marked as valid'

    # Login should be refused with a bad password digest
    bad_K = sha256('badpassword'.encode('UTF-8')).digest()
    assert not server.login(bad_K), 'Bad key digest should be marked as invalid'

    # Now log in without your password by having the client send `A = 0`.
    # Q: What happens when a client sends `A = 0`? What does this do to `S`?
    # A: 0 propagates through `S` calculation on server side, `S = 0`
    server = Server(P)
    salt, B = server.exchange_keys(I, 0)

    zero_K = sha256(str(0).encode('UTF-8')).digest()
    assert server.login(zero_K), 'Zero key digest should work with A = 0'

    # Now log in without your password by having the client send N, N*2, etc.
    # S winds up being a multiple of N, modded by N, so 0 again

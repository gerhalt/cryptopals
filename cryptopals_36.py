#!/usr/bin/env python

from hashlib import sha256
from random import randint

from cryptopals_33 import dh_key, modpow, REAL_P as N


if __name__ == '__main__':
    print('Challenge #36 - Implement Secure Remote Password (SRP)')

    # Both C and S agree on:
    #N = 7
    g = 2
    k = 3
    I = 'anemail@emailer.com'
    P = 'as3c\/r3passes'

    """
    SERVER

    Generate salt as random integer
    Generate string xH=SHA256(salt|password)
    Convert xH to integer x somehow (put 0x on hexdigest)
    Generate v=g**x % N
    Save everything but x, xH
    """
    salt = randint(1, 1000)
    server_xH = sha256((str(salt) + P).encode('UTF-8')).digest()
    x = int.from_bytes(server_xH, byteorder='big') 
    v = modpow(g, x, N)

    # C -> S
    # Send I, A = g ** a % N  (a la Diffie Hellman)
    A, _a = dh_key(N, g)

    # S -> C
    # Send salt, B = kv + g ** b % N
    B, _b = dh_key(N, g)
    B += k * v  # NOTE: unsure if this interpretation of 'kv' is correct

    # S, C
    # Compute string uH = SHA256(A|B), u = integer of uH
    uH = sha256(str(A | B).encode('UTF-8')).digest()
    u = int.from_bytes(uH, byteorder='big')

    """
    CLIENT
    
    Generate string xH=SHA256(salt|password)
    Convert xH to integer x somehow (put 0x on hexdigest)
    Generate S = (B - k * g**x)**(a + u * x) % N
    Generate K = SHA256(S)
    """
    client_xH = sha256((str(salt) + P).encode('UTF-8')).digest()
    #client_S = (B - k * (g ** x)) ** (_a + u * x) % N
    client_S = modpow(B - k * modpow(g, x, N), _a + u * x, N)
    client_K = sha256(str(client_S).encode('UTF-8')).digest()
    
    """
    SERVER

    Generate S = (A * v**u) ** b % N
    Generate K = sha256(S)
    """
    server_S = modpow(A * modpow(v, u, N), _b, N)
    server_K = sha256(str(server_S).encode('UTF-8')).digest()

    # Validation
    # C -> S: Send HMAC-SHA256(K, salt)
    # S -> C: Send "OK" if HMAC-SHA256(K, salt) validates
    assert server_K == client_K, "Server and client K's should match"

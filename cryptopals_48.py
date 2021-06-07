#!/usr/bin/env python
import logging
import os
from collections import defaultdict
from math import log
from random import randint

from cryptopals_33 import modpow
from cryptopals_39 import modinv, RSA


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()


def divceil(a, b) -> int:
    """Returns the result of a // b, rounded up if there is a fractional
    remainder."""
    return -(-a // b)


def int_to_bytes(n: int) -> bytes:
    """Given an integer, converts it to big-endian `bytes` using the least
    number of bytes possible.
    """
    c = int(log(n, 256)) + 1
    return n.to_bytes(c, 'big')


def is_plaintext_pkcs1(rsa: RSA, ciphertext: int) -> bool:
    """Given a private key and an RSA ciphertext, returns whether the last bit
    is odd or even.
    """
    k = len(int_to_bytes(rsa.n))
    plaintext = rsa.decrypt(ciphertext).to_bytes(k, 'big')
    return plaintext[0:2] == b'\x00\x02'


def pkcs1_pad(n: int, msg: bytes) -> bytes:
    """Pads a message using (vulnerable) PKCS #1.5.
    """
    # k is byte length of n (= p * q)
    # |D| is length of data block
    # PS is of length k - 3 - |D|, filled psuedo-randomly
    k = len(int_to_bytes(n))
    if len(msg) > k - 11:
        raise ValueError('Data block length cannot exceed k - 11')

    padding = os.urandom(k - 3 - len(msg))
    return b'\x00\x02' + padding + b'\x00' + msg


if __name__ == '__main__':
    logger.debug("Challenge #48 - Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)")

    rsa = RSA(key_len=768)
    m = int.from_bytes(pkcs1_pad(rsa.n, b'kick it, CC'), 'big')
    c = rsa.encrypt(m)

    B = 1 << 8 * (len(int_to_bytes(rsa.n)) - 2)
    i = 1
    s = {}
    r = {}
    M = defaultdict(list)
    M[0] = [(2*B, 3*B - 1)]

    """
    # Step 1: Blinding
    #     Given an integer c, choose different random integers s0, then check,
    #     by accessing the oracle, whether c(s0) ** e % n is PKCS conforming.
    for _ in range(1, 2000000):
        s[0] = randint(1, rsa.n)
        c0 = (c * modpow(s[0], rsa.e, rsa.n)) % rsa.n
        if is_plaintext_pkcs1(rsa, c0):
            break
    else:
        raise Exception('Unable to find random PKCS-conforming c0')
    logger.debug(f'Found PKCS-conforming c0: {c0}') 
    """

    # If c is PKCS-conforming, s0 <- 1
    s[0] = 1
    c0 = c

    while True:
        # Step 2: Searching for PKCS conforming messages
        if i == 1: 
            # a. Starting the search: If i = 1, then search for the smallest
            #    possible integer such that the ciphertext c0(si) ** e % n is PKCS
            #    conforming.
            s[i] = rsa.n // (3*B)
            while True:
                test_c = (c0 * modpow(s[i], rsa.e, rsa.n)) % rsa.n
                if is_plaintext_pkcs1(rsa, test_c):
                    break
                s[i] += 1
            else:
                raise Exception('Unable to find smallest s1 such that c0(s1 ** e) is PKCS-conforming')

            logger.info(f'#2.a Found smallest s1 (i == 1): {s[i]}')
        elif i > 1 and len(M[i - 1]) >= 2:
            # b. Searching with more than one interval left
            s[i] = s[i - 1] + 1
            while True:
                test_c = (c0 * modpow(s[i], rsa.e, rsa.n)) % rsa.n
                if is_plaintext_pkcs1(rsa, test_c):
                    break
                s[i] += 1
            else:
                raise Exception('Unable to find smallest s1 such that c0(s1 ** e) is PKCS-conforming')

            logger.debug(f'#2.b Found smallest s1: {s[i]}')

        elif len(M[i - 1]) == 1:
            # c. Searching with one interval left
            a, b = M[i - 1][0]
            
            r = 2 * ((b*s[i - 1] - 2*B) // rsa.n)
            s_found = False
            while not s_found:
                s_start = (2*B + r*rsa.n) // b
                s_end = divceil(3*B + r*rsa.n, a)

                for test_s in range(s_start, s_end):  # s_start <= s[i] < s_end
                    test_c = (c0 * modpow(test_s, rsa.e, rsa.n)) % rsa.n
                    s_found = is_plaintext_pkcs1(rsa, test_c)
                    if s_found:
                        break

                r += 1

            s[i] = test_s
            logger.debug(f'#2.c Found ri,si: {r}, {s[i]}')
        else:
            raise Exception('Something went wrong')

        # Step 3: Narrowing the set of solutions
        intervals = set()
        for a,b in M[i - 1]:
            logger.debug(f'Calculating intervals from:')
            logger.debug(f'    a: {a}')
            logger.debug(f'    b: {b}')
            r_start = divceil(a*s[i] - 3*B + 1, rsa.n)
            r_end = (b*s[i] - 2*B) // rsa.n
            logger.debug(f'    {r_start}, {r_end}')
            for r in range(r_start, r_end + 1):  # r_start <= r <= r_end
                interval_start = max(a, divceil(2*B + r*rsa.n, s[i]))
                interval_end = min(b, (3*B - 1 + r*rsa.n) // s[i])
                intervals.add((interval_start, interval_end))
        M[i] = list(intervals)

        logger.debug(f'Built {len(M[i])} intervals:')
        for a,b in M[i]:
            logger.debug(f'    {hex(a)}')
            logger.debug(f'    {hex(b)}')
            logger.debug(f'    m is in interval? {a <= m <= b}')
            logger.debug(f'    {b - a}')
        
        # Step 4: Computing the solution
        if len(M[i]) == 1 and M[i][0][0] == M[i][0][1]:
            a = M[i][0][0]
            discovered_m = a * modinv(s[0], rsa.n) % rsa.n 
            break

        i += 1

    assert discovered_m == m
    logger.info(f'original m:  {hex(m)}')
    logger.info(f'dicovered m: {hex(discovered_m)}')

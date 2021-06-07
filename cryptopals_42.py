#!/usr/bin/env python
from math import ceil

from cryptopals_28 import sha1
from cryptopals_33 import modpow
from cryptopals_39 import RSA


BLOCK_SIZE = 128
E = 3


def inv_pow(x, n):
    upper = 1
    while upper ** n <= x:
        upper *= 2

    lower = upper // 2
    while lower < upper:
        mid = (lower + upper) // 2
        mid_nth = mid ** n
        if lower < mid and mid_nth < x:
            lower = mid
        elif upper > mid and mid_nth > x:
            upper = mid
        else:
            return mid
    return mid + 1


def rsa_sign(rsa: RSA, digest: bytes) -> int:
    """Sign a digest."""
    signature = bytearray()
    signature += b'\x00\x01' + b'\xFF' * (BLOCK_SIZE - 3 - 15 - len(digest)) + b'\x00'

    # TODO: Digest type and length isn't encoded here, which I think is part of
    #       the ASN.1 standard
    signature += (0x3021300906052b0e03021a05000414).to_bytes(15, 'big')  # 120 bits (15 bytes)
    signature += digest

    c = int.from_bytes(signature, 'big')
    m = modpow(c, rsa.d, rsa.n)

    # Important that C be less than the modulo or we lose information
    assert c < rsa.n
    
    return m


def bad_rsa_verification(rsa: RSA, msg: bytes, signature: int) -> bool:
    """Faulty implementation of RSA verification. Instead of checking that the
    0xFF padding occupies the unused portion of the block, simply checks that
    the block looks like `00 01 .. FF 00 ASN.1 HASH`.
    """
    # Reversed encrypt step to verify
    c = modpow(signature, E, rsa.n)
    signature = c.to_bytes(BLOCK_SIZE, 'big')

    print(f'SIG: {signature.hex()}')

    assert signature[:3] == b'\x00\x01\xFF'
    for i in range(3, BLOCK_SIZE - 20):  # SHA1 length
        b = signature[i]
        if b == 0x00:
            i += 1
            break
    else:
        raise ValueError("0x00 padding terminator not found")

    # Add the ASN.1 length, in bytes, for SHA1
    i += 15

    digest = sha1(msg)
    signed_digest = signature[i:i+20]

    print('Digests:')
    print(f'  {digest.hex()}')
    print(f'  {signed_digest.hex()}')
    return digest == signed_digest


if __name__ == '__main__':
    print("Challenge #42 - Bleichenbacher's e=3 RSA Attack")

    original = b'hi mom'
    digest = sha1(original)

    rsa = RSA()
    signature = rsa_sign(rsa, digest)
    assert bad_rsa_verification(rsa, original, signature)

    # digest is 160 bits (20 bytes)
    asn = (0x3021300906052b0e03021a05000414).to_bytes(15, 'big')  # 120 bits (15 bytes)
    d = int.from_bytes(b'\x00' + asn + digest, 'big')

    """
    Attempted to get Hal Kinney's writeup to work on a 1024 bit block, didn't
    have any luck

    from_right = 584
    n = 2 ** 288 - d  # 288 = Length in bits of `00 ASN.1 HASH` 
    print(f'N: {n}')

    root = 2 ** (1009 - 288 - from_right) - (n * (2 ** 34) // 3)
    print(f'ROOT: {root}')
    print(f'RECON: {root ** 3}')
    """

    asn = (0x3021300906052b0e03021a05000414).to_bytes(15, 'big')  # 120 bits (15 bytes)

    padding = 5
    garbage = 128 - (2 + padding + 36)
    n = b'\x00\x01' + (b'\xFF' * padding) + b'\x00' + asn + digest + b'\x00' * garbage

    v = int.from_bytes(n, 'big')

    # Increment the cube root if it's smaller than the actual cube root
    cr = inv_pow(v, 3)
    if cr ** 3 < v:
        cr += 1

    forged = (cr ** 3).to_bytes(128, 'big')

    # Produce only the part we're interested in for closer examination
    print(f'DIGEST: {digest.hex()}')
    print(f'BASE: {n[:128 - garbage + 1].hex()}')
    print(f'RECR: {forged[:128 - garbage + 1].hex()}')

    assert bad_rsa_verification(rsa, original, cr)

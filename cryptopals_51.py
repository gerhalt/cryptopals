#!/usr/bin/env python
import os
import string
import zlib
from functools import partial
from random import choice

from cryptopals_10 import BLOCK_SIZE, cbc_encrypt
from cryptopals_18 import aes_ctr

SESSION_ID = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
REQUEST_FMT = (
    "POST / HTTP/1.1\n"
    "Host: hapless.com\n"
    "Cookie: sessionid={session_id}\n"
    "Content-Length: {content_len}\n"
    "{body}"
)

CHARS = bytes((string.ascii_letters + string.digits + '+/=').encode('utf-8'))


def oracle(plaintext: bytes, encryption='stream') -> int:
    assert encryption in {'stream', 'cipher'}
    
    key = os.urandom(16)
    iv = os.urandom(16)
    
    # Compression
    compressed = zlib.compress(plaintext)

    if encryption == 'stream':
        nonce = int.from_bytes(iv, byteorder='big')
        ciphertext = aes_ctr(key, nonce, compressed)
    elif encryption == 'cipher':
        ciphertext = cbc_encrypt(compressed, key, iv)

    return len(ciphertext)


def request(body: bytes) -> bytes:
    return bytes(REQUEST_FMT.format(
        session_id=SESSION_ID,
        content_len=len(body),
        body=body.decode('utf-8')).encode('utf-8'))


def guess(oracle, known: bytes = None, base_guess: bytes = None, block_align: bool = False) -> bytes:
    """Recursively determines and returns the session_id= string.

    Args:
    - oracle: oracle function to call, accepting a plaintext string and
        returning a length in bytes
    - known: our discovered session_id string, so far
    - base_guess: used when recursing into a set of guesses, when the best
        choice isn't immediately apparently
    - block_align: whether to create a prefix such that adding an incorrect
        character to the ongoing session_id string will roll over the PKCS7
        padding to append a full block
    """
    # Default values
    if base_guess is None:
        base_guess = b''
    if known is None:
        known = b'sessionid='

    last_size = oracle(request(known))
    prefix = b''
    if block_align:
        # Build a prefix such that adding another byte (that doesn't compress down)
        # to the payload makes it block-aligned and the PKCS7 padding adds a full
        # block of new padding to the end of the compressed request
        while True:
            prefix += choice(CHARS).to_bytes(1, byteorder='big')
            size = cbc_oracle(request(prefix + known + base_guess))

            if size - last_size == BLOCK_SIZE:
                prefix = prefix[:-2]  # Back up two bytes
                break

            last_size = size

    known = prefix + known

    best_size = 2 ** 16
    guesses = []
    for i in CHARS:
        i = i.to_bytes(1, byteorder='big')
        r = request(known + base_guess + i)
        size = oracle(r)

        g = base_guess + i
        if size < best_size:
            best_size = size
            guesses = [g]
        elif size == best_size:
            guesses.append(g)

    # If our best size is greater than the last size, we haven't extended our
    # session ID so we can return early
    if best_size > last_size + 1:
        return
    
    guesses = sorted(guesses)
    if len(guesses) > 1:
        for g in guesses:
            guess_result = guess(oracle, known, g, block_align=block_align)
            if guess_result is not None:
                break
    else:
        g = guesses.pop()
        guess_result = guess(oracle, known + g, block_align=block_align)

        # If no deeper match was returned, be sure to append the current best
        # option to the result before returning
        if not guess_result:
            known += g 

    # Finally, strip off any prefix we added for padding
    if guess_result:
        guess_result = guess_result[len(prefix):]

    # If none of our guesses resulted in any better size, return what we knew
    return guess_result or known


if __name__ == '__main__':
    print('Challenge #51 - Compression Ratio Side-Channel Attacks')

    # A. Stream cipher
    guessed_session_id = guess(oracle)[10:]  # Strip off leading 'sessionid='
    assert SESSION_ID == guessed_session_id.decode('utf-8')

    # B. CBC
    cbc_oracle = partial(oracle, encryption='cipher')
    guessed_session_id = guess(cbc_oracle, block_align=True)[10:]  # Strip off leading sessionid=
    assert SESSION_ID == guessed_session_id.decode('utf-8')

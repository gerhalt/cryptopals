#!/usr/bin/env python
import os
import string
import zlib
from functools import partial
from random import choice
from typing import Callable, Optional

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
    """Given a `plaintext`, returns the size of the compressed, encrypted
    ciphertext in bytes.

    Args:
        plaintext: the text to encrypt
        encryption: 'stream' or 'cipher'. Stream uses AES, while 'cbc' uses
            CBC.
    """
    assert encryption in {'stream', 'cbc'}
    
    key = os.urandom(16)
    iv = os.urandom(16)
    
    # Compression
    compressed = zlib.compress(plaintext)

    if encryption == 'stream':
        nonce = int.from_bytes(iv, byteorder='big')
        ciphertext = aes_ctr(key, nonce, compressed)
    elif encryption == 'cbc':
        ciphertext = cbc_encrypt(compressed, key, iv)

    return len(ciphertext)


def request(body: bytes) -> bytes:
    """Creates a populated request payload as defined in the problem statement.

    Args:
        body: the body of the request

    Returns:
        the full payload
    """
    return bytes(REQUEST_FMT.format(
        session_id=SESSION_ID,
        content_len=len(body),
        body=body.decode('utf-8')).encode('utf-8'))


def guess(oracle: Callable[[bytes], bytes], known: bytes = None,
          base_guess: bytes = None, block_align: bool = False
          ) -> Optional[bytes]:
    """Recursively determines and returns the best guess for the
    'sessionid=...' string, including that leading portion..

    Args:
        oracle: oracle function to call, accepting a plaintext string and
            returning a length in bytes
        known: our discovered session_id string, so far
        base_guess: used when recursing into a set of guesses, when the best
            choice isn't immediately apparent
        block_align: whether to create a prefix such that adding an incorrect
            character to the ongoing session_id string will roll over the PKCS7
            padding to append a full block

    Returns:
        The best guess given the `known` bytes, or `None` if all guesses
        appeared equally bad.
    """
    if base_guess is None:
        base_guess = b''
    if known is None:
        known = b'sessionid='

    # NOTE: This doesn't include the `base_guess`, which is why it's passed in
    #       separately.
    known_size = oracle(request(known))

    # The block alignment option allows us to deal with ciphers that use PKCS7
    #
    # Add a character to our prefix string. Check the size of our full payload,
    # including any known and guessed bytes, using the oracle. If the size
    # hasn't increased, repeat.
    #
    # Once the size increases, we strip off *2* bytes, not 1. This allows a
    # guess to increase the length by a single byte without being
    # disqualified. This ALSO has the side effect that nested function calls
    # will not actually change the prefix, because b'XX'[:-2] (or shorter)
    # becomes b''.
    prefix = b''
    if block_align:
        while True:
            prefix += choice(CHARS).to_bytes(1, byteorder='big')
            size = cbc_oracle(request(prefix + known + base_guess))

            if size - known_size == BLOCK_SIZE:
                prefix = prefix[:-2]
                break

    # Prepend the prefix (it'll be stripped off before returning)
    known = prefix + known

    best_guess_size = None
    guesses = []
    for i in CHARS:
        i = i.to_bytes(1, byteorder='big')
        r = request(known + base_guess + i)
        size = oracle(r)

        g = base_guess + i
        if not best_guess_size or size < best_guess_size:
            best_guess_size = size
            guesses = [g]
        elif size == best_guess_size:
            guesses.append(g)

    # If the ciphertext size of our best guess is 2 or more bytes greater than
    # the size of our known payload, stop guessing and immediately return.
    if best_guess_size >= known_size + 2:
        return
    
    # If we have many guesses, all of which result in the same payload size,
    # try all of them, pre
    guesses = sorted(guesses)  # For alphabetic debugging :)
    if len(guesses) > 1:
        for g in guesses:
            guess_result = guess(oracle, known, base_guess=g, block_align=block_align)
            if guess_result is not None:
                break
    else:
        g = guesses.pop()
        guess_result = guess(oracle, known + g, block_align=block_align)

        # No deeper match found, append this call's best guess character
        if not guess_result:
            known += g 

    # Strip off any padding prefix
    if guess_result:
        guess_result = guess_result[len(prefix):]

    # Return the result of our nested guess call(s), or what was already known
    # if the guesses weren't fruitful
    return guess_result or known


if __name__ == '__main__':
    print('Challenge #51 - Compression Ratio Side-Channel Attacks')

    # A. Stream cipher
    guessed_session_id = guess(oracle)
    assert f'sessionid={SESSION_ID}' == guessed_session_id.decode('utf-8')

    # B. CBC
    cbc_oracle = partial(oracle, encryption='cbc')
    while True:
        SESSION_ID = ''.join(map(chr, [choice(CHARS) for _ in range(0, 32)]))
        print(SESSION_ID)

        guessed_session_id = guess(cbc_oracle, block_align=True)
        print(guessed_session_id.decode())
        assert f'sessionid={SESSION_ID}' == guessed_session_id.decode('utf-8')

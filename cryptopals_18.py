#!/usr/bin/env python

from base64 import b64decode

from cryptopals_10 import xor
from cryptopals_13 import aes_encrypt


BLOCK_SIZE = 16

KEY = b'YELLOW SUBMARINE'
NONCE = 0
TEST_INPUT = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
EXPECTED_OUTPUT = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "


def aes_keystream(key: bytes, nonce: int) -> bytes:
    """Generator returning blocks of keystream.
    """
    nonce_chunk = nonce.to_bytes(BLOCK_SIZE // 2, byteorder='little')

    counter = 0
    while True:
        block = nonce_chunk + counter.to_bytes(BLOCK_SIZE // 2, byteorder='little')
        yield aes_encrypt(key, block)
        counter += 1


def aes_ctr(key: bytes, nonce: int, msg: bytes) -> bytes:
    """Encrypts or decrypts a message using AES in CTR mode.
    """
    output = []

    i = 0
    for keystream in aes_keystream(KEY, NONCE):
        block = msg[i:i+BLOCK_SIZE]

        output.append(xor(block, keystream))

        i += BLOCK_SIZE
        if i >= len(msg):
            break
    
    return b''.join(output)


if __name__ == '__main__':
    print('Challenge #18 - Implement CTR, the stream cipher mode')

    ciphertext = b64decode(TEST_INPUT)
    plaintext = aes_ctr(KEY, NONCE, ciphertext)

    assert plaintext == EXPECTED_OUTPUT

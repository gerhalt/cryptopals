#!/usr/bin/env python

from base64 import b64decode

from Crypto.Cipher import AES

from cryptopals_9 import pkcs7_pad 
from cryptopals_15 import pkcs7_strip


BLOCK_SIZE = 16  # bytes


def xor(a: bytes, b: bytes) -> bytes:
    """
    Given two byte arrays of equal length, returns their XOR'ed output.
    """
    assert len(a) == len(b)
    return bytes([i ^ j for i, j in zip(a, b)])


def cbc_encrypt(msg: bytes, key: bytes, iv: bytes = None) -> bytes:
    """
    Encrypt a message with AES in CBC mode. If `iv` is not set, the vector is
    set to all zeroes.
    """
    assert iv is None or len(iv) == BLOCK_SIZE

    cipher = AES.new(key, AES.MODE_ECB)
    padded_msg = pkcs7_pad(msg, BLOCK_SIZE)
    previous_block = iv if iv is not None else b'\x00' * BLOCK_SIZE
    output = []
    for idx in range(0, len(padded_msg), BLOCK_SIZE):
        block = padded_msg[idx:idx+BLOCK_SIZE]

        # XOR with previous block
        xored_block = xor(block, previous_block)
        result = cipher.encrypt(xored_block)

        output.append(result)
        previous_block = result

    return b''.join(output)


def cbc_decrypt(msg: bytes, key: bytes, iv: bytes = None) -> bytes:
    """
    Decrypt a message encrypted with AES in CBC mode. If `iv` is not set, the
    vector is set to all zeroes.
    """
    assert iv is None or len(iv) == BLOCK_SIZE

    cipher = AES.new(key, AES.MODE_ECB)

    previous_block = iv if iv is not None else b'\x00' * BLOCK_SIZE
    output = []
    for idx in range(0, len(msg), BLOCK_SIZE):
        block = msg[idx : idx + BLOCK_SIZE]

        block_output = cipher.decrypt(block)

        plaintext = xor(block_output, previous_block)
        output.append(plaintext)

        previous_block = block

    return b''.join(output)


if __name__ == '__main__':
    print('Challenge #10 - Implement CBC Mode')

    key = b'YELLOW SUBMARINE'
    msg = b'josh' * 1000
    iv = b'\x00' * BLOCK_SIZE

    # Double check the input and the output are the same, ignoring any trailing
    # padding on the decrypted message
    encrypted_msg = cbc_encrypt(msg, key, iv)
    decrypted = cbc_decrypt(encrypted_msg, key, iv)
    assert msg == decrypted[:len(msg)]

    # Test file
    with open('data/10.txt', 'rb') as f:
        msg = b64decode(f.read())

        decrypted = cbc_decrypt(msg, b'YELLOW SUBMARINE', b'\x00' * BLOCK_SIZE)
        print(decrypted)

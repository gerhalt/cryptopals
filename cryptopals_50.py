#!/usr/bin/env python
import os

from cryptopals_9 import pkcs7_pad
from cryptopals_10 import BLOCK_SIZE, cbc_encrypt, xor


if __name__ == '__main__':
    print("Challenge #50 - Hashing with CBC-MAC")

    # Generate our original MAC 
    ORIGINAL_MSG = b"alert('MZA who was that?');\n"
    KEY = b'YELLOW SUBMARINE'
    IV = int.to_bytes(0, BLOCK_SIZE, byteorder='big')
    ciphertext = cbc_encrypt(ORIGINAL_MSG, key=KEY, iv=IV)

    og_mac = ciphertext[-BLOCK_SIZE:]
    print(f'Original MAC: {og_mac.hex()}')

    # Build the original input block that, when fed into the cipher,
    # produces the MAC, by XORing the second to last block of ciphertext with
    # the last padded block of input
    last_og_block = pkcs7_pad(ORIGINAL_MSG)[-BLOCK_SIZE:]
    previous_ct_block = ciphertext[-2*BLOCK_SIZE:-BLOCK_SIZE]
    og_cipher_input = xor(previous_ct_block, last_og_block)

    # Our hacked message will also be padded. To address this, we will trim off
    # the final byte of the hacked block and expect it to be populated with a
    # single PKCS7 padding byte (0x01). To make this work, we:
    #
    # 1. Calculate the last cipher input byte by XORing the last original
    #     cipher byte with 0x01.
    # 2. Generate garbage blocks with random input until we find one whose last
    #     byte *of ciphertext* matches the final byte we're looking for.
    # 3. Pad our base message and append the garbage block.
    # 4. XOR cipher input from our original message we built above with the
    #     ciphertext of our garbage block.
    # 5. Trim off the very last byte of the message (again, automatically
    #     padded with 0x01)
    # 6. Calcate the MAC as usual. It should match our original, "good" MAC

    last_byte = 0x01 ^ og_cipher_input[-1]

    # Pad the message, then find a random block that, when encrypted, has the
    # final byte we're looking for
    hacked_base = pkcs7_pad(b"alert('Ayo, the Wu is back!');//")
    while True:
        garbage_block = os.urandom(BLOCK_SIZE)

        # NOTE: The block we'll work with here is the second to last block,
        #       since the last one is generated from the full block of padding
        garbage_ciphertext = cbc_encrypt(hacked_base + garbage_block, key=KEY, iv=IV)[-BLOCK_SIZE*2:-BLOCK_SIZE]
        if garbage_ciphertext[-1] == last_byte:
            break

    hacked_msg = hacked_base + garbage_block + xor(og_cipher_input, garbage_ciphertext)

    # Trim off the final byte, to be replaced with padding, and calculate the MAC
    hacked_msg = hacked_msg[:-1]
    hacked_mac = cbc_encrypt(hacked_msg, key=KEY, iv=IV)[-BLOCK_SIZE:]
    print(f'Hacked MAC: {hacked_mac.hex()}')

    assert og_mac == hacked_mac

#!/usr/bin/env python


def pkcs7_pad(msg: bytes, block_size: int) -> bytes:
    """
    Pads the input message to the `block_size` by appending bytes to the end of
    the block, creating a message length that is a multiple of the block size.
    If the message length is already a multiple of `block_size`, appends a full
    block of padding. `block_size` must be less than 256.
    """
    assert block_size < 256
    
    padding = block_size - (len(msg) % block_size)

    return msg + bytes([padding] * padding)


if __name__ == '__main__':
    print('Challenge #9 - Implemented PKCS#7 Padding')

    assert pkcs7_pad(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'

    # Empty block case
    assert pkcs7_pad(b'', 8) == b'\x08' * 8

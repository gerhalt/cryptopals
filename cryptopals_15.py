#!/usr/bin/env python


def pkcs7_strip(msg: bytes) -> bytes:
    """
    Given an input `msg`, returns the string stripped of all padding if it was
    padding correctly. If not, throws a `ValueError`.
    """
    if len(msg) % 16:
        raise ValueError(f'Message is not not a multiple of 16 bytes ({len(msg)})')

    padding_count = msg[-1]
    if padding_count > 16:
        raise ValueError(f'Padding value must not exceed block size ({padding_count})')

    #print(f'Should be {padding_count} elements, each set to {padding_count}')
    if not all(map(lambda x: x == padding_count, msg[-padding_count:])):
        raise ValueError(f'Last {padding_count} bytes not all set to {padding_count}')

    return msg[:-padding_count]

if __name__ == '__main__':
    print('Challenge #15 - PKCS#7 Padding Validation')

    try:
        # Failure, message length isn't multiple of 16
        pkcs7_strip(b'jo' + b'\xFA' * 12)
        raise Exception("Failure")
    except ValueError:
        pass

    try:
        # Failure, padding count indicates 250 bytes of padding but it can't
        # exceed 16
        assert pkcs7_strip(b'jo' + b'\xFA' * 12)
        raise Exception("Failure")
    except ValueError:
        pass

    # Message is 16 bytes, padding indicates 12 bytes with all 12 bytes
    # set to 12
    assert pkcs7_strip(b'josh' + b'\x0C' * 12) == b'josh'

    # Message is 32 bytes, last block entirely padding
    assert pkcs7_strip(b'j' * 16 + b'\x10' * 16) == b'j' * 16

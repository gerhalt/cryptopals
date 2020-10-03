#!/usr/bin/env python


def is_pkcs7(msg: bytes) -> bytes:
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
    return all(map(lambda x: x == padding_count, msg[-padding_count:]))

if __name__ == '__main__':
    print('Challenge #15 - PKCS#7 Padding Validation')

    try:
        # Failure, message length isn't multiple of 16
        is_pkcs7(b'jo' + b'\xFA' * 12)
        raise Exception("Failure")
    except ValueError:
        pass

    try:
        # Failure, padding count indicates 250 bytes of padding but it can't
        # exceed 16
        assert is_pkcs7(b'jo' + b'\xFA' * 12)
        raise Exception("Failure")
    except ValueError:
        pass

    # Pass, message is 16 bytes, padding indicates 12 bytes with all 12 bytes
    # set to 12
    assert is_pkcs7(b'josh' + b'\x0C' * 12)

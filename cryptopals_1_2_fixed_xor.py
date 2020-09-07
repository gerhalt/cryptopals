#!/usr/bin/env python

from helpers import hex_str_to_b64, hex_str_to_int


def fixed_xor(a: str, b: str) -> str:
    """
    Given two equal length strings, converts each to hex and outputs the
    XOR combination as a hexadecimal string.
    """

    out = []
    for i in range(0, len(a), 2):
        a_byte = hex_str_to_int(a[i:i+2])
        b_byte = hex_str_to_int(b[i:i+2])
        out.append('{:02x}'.format(a_byte ^ b_byte))

    return ''.join(out)


if __name__ == '__main__':
    print('Challenge #2 - Fixed XOR')

    test_in_a = '1c0111001f010100061a024b53535009181c'
    test_in_b = '686974207468652062756c6c277320657965'
    test_out = '746865206b696420646f6e277420706c6179'

    actual_out = fixed_xor(test_in_a, test_in_b)
    assert(actual_out == test_out)

    print(hex_str_to_b64(actual_out))

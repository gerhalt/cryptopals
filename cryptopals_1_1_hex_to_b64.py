#!/usr/bin/env python

import itertools


B64_LOOKUP = [chr(i) for i in itertools.chain(
    range(65, 91),   # A-Z
    range(97, 123),  # a-z
    range(48, 58),   # 0-9
    [43, 47]         # '+', '/'
)]


def hex_str_to_int(inp: str) -> int:
    """
    Converts a hexadecimal string to an integer.
    """

    # Convert to lowercase so we don't need to worry about A-F
    inp = inp.lower()

    output = 0
    for c in inp:
        output *= 16

        v = ord(c)
        if 48 <= v <= 57:  # 0 - 9
            v -= 48
        elif 97 <= v <= 102:  # a - f
            v -= 87  # So the value winds up being 10-16
        else:
            raise ValueError(f'\'{c}\' is not a valid hexadecimal symbol') 
        
        output += v

    return output


def hex_str_to_b64(inp: str) -> str:
    """
    Converts a hexadecimal string to a base64 string.
    """
    if not inp:
        return ''

    # Convert the string to an integer, will crash if the string is invalid
    number = hex_str_to_int(inp)

    output = []
    while number:
        last = number % 64
        number = number // 64 

        output.append(B64_LOOKUP[last])

    return ''.join(output[::-1])


if __name__ == '__main__':
    print('Challenge #1 - Hex to B64')

    test_input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    test_output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    out = hex_str_to_b64(test_input)
    assert(out == test_output)

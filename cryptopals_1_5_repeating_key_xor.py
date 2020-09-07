#!/usr/bin/env python


def repeating_key_xor(k: str, s: str) -> bytes:
    """ Sequentially XOR's each byte of `k` against the corresponding byte of
    `s`. When the end of the key is reached, we loop back to the start and
    continue.
    """
    out = []
    for i, c in enumerate(s):
        k_byte = k[i % len(k)]
        out.append(k_byte ^ c)

    return bytes(out)


if __name__ == '__main__':
    print('Challenge #5 - Repeating Key XOR')

    s = (b"Burning 'em, if you ain't quick and nimble\n"
         b"I go crazy when I hear a cymbal")
    key = b"ICE"

    out = ''.join(['{:02x}'.format(b) for b in repeating_key_xor(key, s)])
    expected_out = (
        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    )
    assert(out == expected_out)

    print(out)

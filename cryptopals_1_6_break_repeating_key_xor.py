#!/usr/bin/env python

import base64

from helpers import byte_xor_guesser, repeating_key_xor


def hamming_distance(a: str, b: str) -> int:
    """ Calculates the hamming distance (number of different bits) between two strings.
    """
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        raise TypeError('Expected bytes')
    if len(a) != len(b):
        raise ValueError('String lengths must be equal')

    differing_byte_count = 0
    for byte_a, byte_b in zip(a, b):
        mask = 0b00000001
        for i in range(0, 8):
            if (byte_a ^ byte_b) & mask:
                differing_byte_count += 1
            mask = mask << 1

    return differing_byte_count


if __name__ == '__main__':
    print('Challenge #6 - Break Repeating-Key XOR')

    a = b'this is a test'
    b = b'wokka wokka!!!'
    assert(hamming_distance(a, b) == 37)

    with open('data/1.6.txt', 'rb') as f:
        # Encoded in B64 initially
        text = base64.b64decode(f.read())

        scores = []
        for keysize in range(2, 40):
            # Check and average multiple blocks
            score = 0

            average_over = min(len(text) // keysize, 12)
            for group in range(0, average_over, 2):
                start = group * keysize
                block_a = text[start:start + keysize]
                block_b = text[start + keysize:start + keysize * 2]

                score += hamming_distance(block_a, block_b)

            n = score / (average_over // 2) / keysize
            scores.append((n, keysize))

        # Sort the scores, ordered from smallest 
        scores.sort(key=lambda x: x[0])
        for s, keysize in scores[:1]:  # Try the top X
            print(f'Keysize is {keysize}')
            transposed_chunks = []

            # Break the ciphertext into KEYSIZE-d chunks
            block = 0
            while block * keysize < len(text):
                chunk = text[block * keysize:(block + 1) * keysize]

                for idx, b in enumerate(chunk):
                    if block == 0:
                        transposed_chunks.append([b])
                    else:
                        transposed_chunks[idx].append(b)

                block += 1

            # Build the repeating key from each chunk, in order
            repeating_key = []
            for tc in transposed_chunks:
                tc_hex = ''.join(['{:02x}'.format(b) for b in tc])
                score, tc_key, _ = byte_xor_guesser(tc_hex)
                repeating_key.append(tc_key)

        print(repeating_key_xor(repeating_key, text))

#!/usr/bin/env python
import os
from collections import namedtuple
from functools import partial

from Crypto.Cipher import AES

from cryptopals_52 import cipher, merkle_damgard

ExpandableBlock = namedtuple('ExpandableBlock', ['short', 'long', 'hash'])


if __name__ == '__main__':
    print("Challenge #53 - Kelsey and Schneier's Expandable Messages")

    # Skip padding the message, as it throws off our hashing. We'll take care
    # of the padding ourselves, if needed
    merkle_damgard = partial(merkle_damgard, pad_msg=False)

    INITIAL_H = os.urandom(16)
    K = 5

    message_chunks = []
    current_h = INITIAL_H
    for i in range(1, K+1):  # Iterate from 2**(K-1) + 1 to 2**0 + 1 (aka 2**(K-K) + 1)
        # Generate a single block to collide multiple blocks against
        single_block = os.urandom(16)
        single_block_h = merkle_damgard(single_block, current_h, cipher)

        # Hash K - 1 dummy blocks so we can create new hashes just by
        # generating a single last block and appending it
        dummy_blocks = os.urandom(16 * (2**(K-i)))
        dummy_h = merkle_damgard(dummy_blocks, current_h, cipher)

        while True:
            last_block = os.urandom(16)
            long_h = merkle_damgard(last_block, dummy_h, cipher) 

            assert long_h == merkle_damgard(dummy_blocks+last_block, current_h, cipher)

            if single_block_h == long_h:
                break

        current_h = long_h

        print(f'Matched message length {i}')
        print(f'{single_block.hex()} -> {single_block_h.hex()}')
        print(f'{last_block.hex()} -> {long_h.hex()}')
        message_chunks.append(ExpandableBlock(short=single_block,
                                              long=dummy_blocks+last_block,
                                              hash=long_h))

    last_expandable_h = current_h

    # Now, the actual attack on a message M of length 2^K
    M = b''
    current_h = INITIAL_H
    intermediate_hs = {}
    for block_idx in range(0, 2**K):
        block = os.urandom(16)
        M += block

        # NOTE: Should we skip storing the first K blocks?
        #       We know that the prefix will be, at minimum, length K - 1
        if block_idx < K:
            continue

        intermediate_hs[current_h] = block_idx
        current_h = merkle_damgard(block, current_h, cipher)

    M_H = current_h
    print(f"Message M has length {len(M) // 16} with a final hash of {M_H.hex()}")

    # Find the bridge block
    while True:
        bridge = os.urandom(16)
        test_h = merkle_damgard(bridge, last_expandable_h, cipher)

        if test_h in intermediate_hs:
            intermediate_idx = intermediate_hs[test_h]
            break

    print(f"Intermediate block index is {intermediate_idx}")

    # To use our expandable message, we need to calculate which blocks should
    # be expanded or contracted. We know  

    prefix_blocks = b''
    s = intermediate_idx - 1 - K
    for i in range(0, K):
        chunk = message_chunks[i]
        expand_block = (s >> (K - i - 1)) % 2 == 1
        prefix_blocks += chunk.long if expand_block else chunk.short

    hacked_msg = prefix_blocks + bridge + M[intermediate_idx * 16:]
    hacked_h = merkle_damgard(hacked_msg, INITIAL_H, cipher)

    print(f'Original message: {M.hex()}')
    print(f'Hacked message:   {hacked_msg.hex()}')
    print(f'Original H: {M_H.hex()}')
    print(f'Hacked H:   {hacked_h.hex()}')

    assert M_H == hacked_h 

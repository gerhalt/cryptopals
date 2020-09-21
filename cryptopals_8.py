#!/usr/bin/env python

from collections import defaultdict


def detect_duplicate_blocks(msg: bytes, block_size: int = 16) -> int:
    """
    Given a message and a block size, returns a dictionary of
    `block`->`count` key-value pairs for any blocks found more than once.
    """
    counts = defaultdict(int)
    for i in range(0, len(msg), block_size):
        chunk = msg[i:i + block_size]
        counts[chunk] += 1

    return {block: score for block, score in counts.items() if score > 1}


if __name__ == '__main__':
    print('Challenge #8 - Detect line encrypted with ECB')

    chunks = []
    with open('data/8.txt', 'r') as f:
        for line in f:
            line = line.strip()
            chunks.append(bytes.fromhex(line))

    msg = b''.join(chunks)

    duplicate_blocks = detect_duplicate_blocks(msg)
    for block, count in duplicate_blocks.items():
        print(f'    {count} identical blocks: {block}')

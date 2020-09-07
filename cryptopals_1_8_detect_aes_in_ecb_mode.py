#!/usr/bin/env python


from collections import defaultdict


if __name__ == '__main__':
    print('Challenge #8 - Detect line encrypted with ECB')

    with open('data/1_8.txt', 'r') as f:
        for line in f:
            line = line.strip()
            line = bytes.fromhex(line)

            # Break into 16 byte chunks, record each time we see the same block
            # Because the same plaintext 16 byte block will output the same
            # encrypted block, we look for duplicate byte blocks for this basic
            # puzzle. Convenient.
            counts = defaultdict(int)
            for i in range(0, len(line), 16):
                chunk = line[i:i + 16]
                counts[chunk] += 1

            # Look for any line with duplicate blocks
            score = sum([c for c in counts.values() if c > 1])
            if score > 0:
                print(line)
                for block, count in counts.items():
                    if count > 1:
                        print(f'    {count} identical blocks: {block}')

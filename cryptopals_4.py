#!/usr/bin/env python

from cryptopals_3 import byte_xor_guesser


if __name__ == '__main__':
    print('Challenge #4 - Detect Single Character XOR')

    best_guess = None
    with open('data/4.txt', 'rb') as f:
        for line in f:
            line = line.strip()
            current_guess = byte_xor_guesser(line)
            if not best_guess or current_guess[0] > best_guess[0]:
                best_guess = current_guess

    print('{:.3f} {}'.format(best_guess[0], best_guess[2]))

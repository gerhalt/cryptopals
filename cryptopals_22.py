#!/usr/bin/env python

import time
from calendar import timegm
from datetime import datetime
from random import randint

from cryptopals_21 import MersenneTwister


if __name__ == '__main__':
    print('Challenge #21 - Crack a MT19937 seed')

    print('Waiting to generate a seed')
    time.sleep(randint(40, 1000))

    now_epoch = timegm(datetime.utcnow().timetuple())
    mt = MersenneTwister(now_epoch)

    print('Seed generated, waiting to generate a number')
    time.sleep(randint(40, 1000))

    print('Generating number') 
    first_n = mt.extract_number()

    print('Working backwards from the present to determine seed')
    test_time = timegm(datetime.utcnow().timetuple())
    test_limit = test_time - 60 * 60
    while test_time > test_limit:
        mt.seed(test_time)
        test_n = mt.extract_number()

        if test_n == first_n:
            print(f'Found matching seed: {test_time}')
            break

        test_time -= 1

#!/usr/bin/env python3
import crypto.utils

# https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange

# Common
p = 41843
x = 2

# Alice
a = crypto.utils.get_random_number(p)
A = crypto.utils.powmod(x, a, p)

# Beat
b = crypto.utils.get_random_number(p)
B = crypto.utils.powmod(x, b, p)

# Exchange
print('Alice:', A, 'Beat:', B)

# Compute common key
GA = crypto.utils.powmod(B, a, p)
GB = crypto.utils.powmod(A, b, p)
print(GA, GB)
assert GA == GB

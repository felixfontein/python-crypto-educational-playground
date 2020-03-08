#!/usr/bin/env python3
import crypto.utils

# https://en.wikipedia.org/wiki/Three-pass_protocol#Shamir_three-pass_protocol

# Common
p = 41843

# Setup Alice
eA = (3 + crypto.utils.get_random_number(p - 4)) | 1
gcd, dA, _ = crypto.utils.extended_gcd(eA, p - 1)
assert gcd == 1
dA = dA % (p - 1)

# Setup Beat
eB = (3 + crypto.utils.get_random_number(p - 4)) | 1
gcd, dB, _ = crypto.utils.extended_gcd(eB, p - 1)
assert gcd == 1
dB = dB % (p - 1)

# ################################

# Alice: encrypts message
m = crypto.utils.get_random_number(p)
M1 = crypto.utils.powmod(m, eA, p)
print(M1)

# Beat: also encrypt
M2 = crypto.utils.powmod(M1, eB, p)
print(M2)

# Alice: decrypt
M3 = crypto.utils.powmod(M2, dA, p)
print(M3)

# Beat: decrypt
M4 = crypto.utils.powmod(M3, dB, p)
print(M4)
assert m == M4

"""
Provides various helping functions used in cryptography:
 * bitwise rotation
 * computing GCD and extended GCD
 * fast modular exponentiation
 * randomized Miller-Rabin primality test
 * finding prime numbers

WARNING: These implementations are for educational purposes.
         DO NOT use them for real-world applications!

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import os


# ###################################################################
# ## Bitwise rotations

def ROL(value, offset, bitsize):
    """Rotates the value ``value`` by ``offset`` bits to the left.

    Assumes that the value uses at most ``bitsize`` bits."""
    result = (value << offset) & ((1 << bitsize) - 1)
    return result | (value >> (bitsize - offset))


def ROR(value, offset, bitsize):
    """Rotates the value ``value`` by ``offset`` bits to the right.

    Assumes that the value uses at most ``bitsize`` bits."""
    result = (value << (bitsize - offset)) & ((1 << bitsize) - 1)
    return result | (value >> offset)


# ###################################################################
# ## Basic number-theoretic functions

def gcd(a, b):
    """Return a greatest common divisor of the inputs."""
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """Return a greatest common divisor of the inputs with a Bézout equation.

    Returns a tuple ``(gcd, x, y)``, where ``gcd`` is a greatest
    common divisor of ``a`` and ``b``, and where ``x``, ``y``
    satisfy the Bézout equation ``gcd == a * x + b * y``.
    """
    ai = b    # ai stands for: a with index i
    aim1 = a  # aim1 stands for: a with index i-1
    bim1, bi = 1, 0
    cim1, ci = 0, 1
    while ai != 0:
        q, r = divmod(aim1, ai)  # compute both quot. and remainder
        aim1, ai = ai, r
        bim1, bi = bi, bim1 - q * bi
        cim1, ci = ci, cim1 - q * ci
    return aim1, bim1, cim1


def powmod(base, exponent, modulus):
    """Compute basis ** exponent modulo modulus."""
    n = exponent.bit_length()
    result = 1
    for i in reversed(range(n)):
        result = (result * result) % modulus
        if exponent & (1 << i):
            result = (result * base) % modulus
    return result


# ###################################################################
# ## Randomized primality tests

def miller_rabin(p, a):
    """Does one iteration of Miller-Rabin for p with base a."""
    m = p - 1
    a_prev = a
    n = 0
    while m % 2 == 0:
        m //= 2
        n += 1
    a = powmod(a, m, p)
    if a in (1, p - 1):
        return True
    for _ in range(n):
        a_prev, a = a, (a * a) % p
        if a == 1:
            return a_prev == p - 1
    return False


def is_probable_prime(p, mr_tries=100):
    """Test whether p is a probable prime."""
    # 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29 == 6469693230
    if gcd(p, 6469693230) > 1:
        return False
    # Do Miller-Rabin with some random bases
    for _ in range(mr_tries):
        a = int.from_bytes(os.urandom(3), byteorder='big')
        if not miller_rabin(p, a):
            return False
    return True


def find_prime(number_of_bits):
    """Find a random prime number p with
       p.bit_length() == number_of_bits."""
    while True:
        # Create a random number of number_of_bits bits
        number_of_bytes = (number_of_bits + 7) // 8
        random_bytes = os.urandom(number_of_bytes)
        num = int.from_bytes(random_bytes, byteorder='big')
        # Make sure that num satisfies
        # num.bit_length() == number_of_bits
        b = num.bit_length()
        if b > number_of_bits:
            num >>= b - number_of_bits
        elif b < number_of_bits:
            num |= 1 << (number_of_bits - 1)
        # Make sure the number is odd
        num |= 1
        # Check for probable primes
        if is_probable_prime(num):
            return num
        # If this is not the case, try another number (while loop)


def find_safe_prime(number_of_bits):
    """Find a random safe-prime number p with
       p.bit_length() == number_of_bits.

    WARNING: this implementation is *very slow*!
    """
    while True:
        p = 2 * find_prime(number_of_bits - 1) + 1
        if p.bit_length() == number_of_bits and is_probable_prime(p):
            return p

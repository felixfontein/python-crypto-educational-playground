"""
Implements the SHA-2-256 hash function.

WARNING: These implementations are for educational purposes.
         DO NOT use them for real-world applications!

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import typing

from .utils import ROR

from .padding import add_sha2_padding


def merkle_damgard(compression_function: typing.Callable[[bytes], bytes],
                   compression_input_len: int,
                   compression_output_len: int,
                   padding: typing.Callable[[bytes, int], bytes],
                   IV: bytes) -> typing.Callable[[bytes], bytes]:
    """Create hash function from compression function.

    Uses the Merkle-Damgård construction.
    """
    blocksize = compression_input_len - compression_output_len
    assert len(IV) == compression_output_len

    def f(data: bytes) -> bytes:
        padded_data = padding(data, blocksize)
        value = IV
        for i in range(0, len(padded_data), blocksize):
            value = compression_function(value + padded_data[i:i + blocksize])
        return value

    return f


def _split(data: bytes) -> typing.List[int]:
    result = [None] * (len(data) // 4)
    idx = 0
    for i in range(0, len(data), 4):
        result[idx] = int.from_bytes(data[i:i + 4], byteorder='big')
        idx += 1
    return result


def _combine(data: typing.List[int]) -> bytes:
    return b''.join([v.to_bytes(4, byteorder='big') for v in data])


SHA_2_256_IV_DATA = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

SHA_2_256_IV = _combine(SHA_2_256_IV_DATA)

SHA_2_256_ROUND_CONSTANTS = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]


def _sha2_256_encrypt(input_bytes: bytes) -> bytes:
    """The SHA-2-256 internal block cipher (Davies-Meyer construction)."""
    # Split input into 32bit ints
    value = _split(input_bytes[:32])
    key = _split(input_bytes[32:])

    # Key extension
    for i in range(16, 64):
        v1 = ROR(key[i - 15], 7, 32)
        v1 ^= ROR(key[i - 15], 18, 32)
        v1 ^= (key[i - 15] >> 3)
        v2 = ROR(key[i - 2], 17, 32)
        v2 ^= ROR(key[i - 2], 19, 32)
        v2 ^= (key[i - 2] >> 10)
        key.append((key[i - 16] + key[i - 7] + v1 + v2) & 0xFFFFFFFF)

    # Message schedule
    r = value
    for i in range(64):
        S1 = ROR(r[4], 6, 32) ^ ROR(r[4], 11, 32) ^ ROR(r[4], 25, 32)
        ch = (r[4] & r[5]) ^ ((~r[4]) & r[6])
        temp1 = r[7] + S1 + ch + SHA_2_256_ROUND_CONSTANTS[i] + key[i]
        S0 = ROR(r[0], 2, 32) ^ ROR(r[0], 13, 32) ^ ROR(r[0], 22, 32)
        maj = (r[0] & r[1]) ^ (r[0] & r[2]) ^ (r[1] & r[2])
        temp2 = S0 + maj
        r = [
            (temp1 + temp2) & 0xFFFFFFFF,
            r[0],
            r[1],
            r[2],
            (r[3] + temp1) & 0xFFFFFFFF,
            r[4],
            r[5],
            r[6],
        ]

    # Combine result
    return _combine([(a + b) & 0xFFFFFFFF for a, b in zip(value, r)])


sha_2_256 = merkle_damgard(
    _sha2_256_encrypt,
    32 + 64,
    32,
    add_sha2_padding,
    SHA_2_256_IV,
)

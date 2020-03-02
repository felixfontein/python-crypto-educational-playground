"""
Implements the AES encryption.

WARNING: These implementations are for educational purposes.
         DO NOT use them for real-world applications!

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import typing

from .utils import ROL

from .cipher import BlockCipher


def _poly_mul(a: int, b: int) -> int:
    """Compute ``a * b`` as polynomials in Z_2[X]."""
    res = 0
    while b:
        if b & 1:
            res ^= a
        a <<= 1
        b >>= 1
    return res


def _poly_div(a: int, b: int) -> int:
    """Long division of ``a`` and ``b`` as polynomials in Z_2[X]."""
    bl = b.bit_length() - 1
    d = a.bit_length() - (bl + 1)
    if d < 0:
        return 0, a
    res = 0
    while d >= 0:
        if a & (1 << (d + bl)):
            a ^= b << d
            res ^= 1 << d
        d -= 1
    return res, a


def _poly_gcd_ex(a: int, b: int) -> int:
    """Compute GCD of ``a`` and ``b`` as polynomials in Z_2[X].

    Returns a tuple ``(gcd, x, y)`` such that ``gcd`` is the GCD of ``a``
    and ``b`` and that ``gcd == a * x + b * y`` in ``Z_2[X]``.
    """
    ai = b    # ai stands for: a with index i
    aim1 = a  # aim1 stands for: a with index i-1
    bim1, bi = 1, 0
    cim1, ci = 0, 1
    while ai != 0:
        q, r = _poly_div(aim1, ai)
        aim1, ai = ai, r
        bim1, bi = bi, bim1 ^ _poly_mul(q, bi)
        cim1, ci = ci, cim1 ^ _poly_mul(q, ci)
    return aim1, bim1, cim1


def _multiply(x: int, y: int) -> int:
    """Compute ``x * y`` in Z_2[X]<X^8 + X^4 + X^3 + X + 1>."""
    return _poly_div(_poly_mul(x, y), 0b100011011)[1]


def _sbox(v: int) -> int:
    """Compute the value of the AES S-Box for ``v``."""
    # Inversion in Z_2[X]/<X^8 + X^4 + X^3 + X + 1>
    if v:
        gcd, x, _ = _poly_gcd_ex(v, 0b100011011)
        assert gcd == 1
        assert _multiply(v, x) == 1
        v = x
    # Affine operation in Z_2[X]/<X^8 + 1>
    v ^= ROL(v, 1, 8) ^ ROL(v, 2, 8) ^ ROL(v, 3, 8) ^ ROL(v, 4, 8)
    v ^= 0b01100011
    return v


def _compute_inverse_sbox(sbox):
    result = [0] * 256
    for i, v in enumerate(sbox):
        result[v] = i
    return result


AES_S_BOX = [_sbox(v) for v in range(256)]
AES_S_BOX_INVERSE = _compute_inverse_sbox(AES_S_BOX)

AES_MIX_COLUMNS = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]

AES_MIX_COLUMNS_INV = [
    [0xe, 0xb, 0xd, 0x9],
    [0x9, 0xe, 0xb, 0xd],
    [0xd, 0x9, 0xe, 0xb],
    [0xb, 0xd, 0x9, 0xe],
]

_AES_ROUND_CONSTANTS = [v << 24 for v in [
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36,
]]


def _to_matrix(v: typing.List[int]) -> typing.List[typing.List[int]]:
    """Convert list of 32bit words to byte matrix."""
    return [
        [(v[j] >> (8 * (3 - i))) & 0xFF for j in range(4)] for i in range(4)
    ]


def _from_matrix(v: typing.List[typing.List[int]]) -> typing.List[int]:
    """Convert byte matrix to list of 32bit words."""
    return [
        sum([v[j][i] << ((3 - j) * 8) for j in range(4)]) for i in range(4)
    ]


def _shift_rows(v: typing.List[int]) -> typing.List[int]:
    """Compute the ShiftRows operation."""
    return [
        [v[0][0], v[0][1], v[0][2], v[0][3]],
        [v[1][1], v[1][2], v[1][3], v[1][0]],
        [v[2][2], v[2][3], v[2][0], v[2][1]],
        [v[3][3], v[3][0], v[3][1], v[3][2]],
    ]


def _inv_shift_rows(v: typing.List[int]) -> typing.List[int]:
    """Compute the InvShiftRows operation."""
    return [
        [v[0][0], v[0][1], v[0][2], v[0][3]],
        [v[1][3], v[1][0], v[1][1], v[1][2]],
        [v[2][2], v[2][3], v[2][0], v[2][1]],
        [v[3][1], v[3][2], v[3][3], v[3][0]],
    ]


def _mix_columns(matrix: typing.List[typing.List[int]]
                 ) -> typing.List[typing.List[int]]:
    """Compute the MixColumns operation."""
    result = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            v = 0
            for k in range(4):
                v ^= _multiply(AES_MIX_COLUMNS[i][k], matrix[k][j])
            result[i][j] = v
    return result


def _inv_mix_columns(matrix: typing.List[typing.List[int]]
                     ) -> typing.List[typing.List[int]]:
    """Compute the MixColumns operation."""
    result = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            v = 0
            for k in range(4):
                v ^= _multiply(AES_MIX_COLUMNS_INV[i][k], matrix[k][j])
            result[i][j] = v
    return result


def _sub_word(v: int) -> int:
    """Compute the SubWord operation."""
    return (
        AES_S_BOX[v & 0xFF]
        | (AES_S_BOX[(v >> 8) & 0xFF] << 8)
        | (AES_S_BOX[(v >> 16) & 0xFF] << 16)
        | (AES_S_BOX[(v >> 24) & 0xFF] << 24)
    )


def _inv_sub_word(v: int) -> int:
    """Compute the InvSubWord operation."""
    return (
        AES_S_BOX_INVERSE[v & 0xFF]
        | (AES_S_BOX_INVERSE[(v >> 8) & 0xFF] << 8)
        | (AES_S_BOX_INVERSE[(v >> 16) & 0xFF] << 16)
        | (AES_S_BOX_INVERSE[(v >> 24) & 0xFF] << 24)
    )


def _rot_word(v: int) -> int:
    """Compute the RotWord operation."""
    return ROL(v, 8, 32)


def _key_schedule(key: typing.List[int]) -> typing.List[int]:
    """Compute the Rijndael key schedule."""
    result = [0] * 60
    result[0:8] = key
    for i in range(8, 60):
        if i % 8 == 0:
            result[i] = result[i - 8] ^ _sub_word(_rot_word(result[i - 1]))
            result[i] ^= _AES_ROUND_CONSTANTS[i // 8]
        elif i % 8 == 4:
            result[i] = result[i - 8] ^ _sub_word(result[i - 1])
        else:
            result[i] = result[i - 8] ^ result[i - 1]
    return result


def _split(v: bytes) -> typing.List[int]:
    """Split a bytestring into a list of 32bit words."""
    return [
        int.from_bytes(v[i:i + 4], byteorder='big')
        for i in range(0, len(v), 4)
    ]


def _combine(v: typing.List[int]) -> bytes:
    """Combine a bytestring from a list of 32bit words."""
    return b''.join([int.to_bytes(val, 4, byteorder='big') for val in v])


def aes_encrypt(message: bytes, key: bytes) -> bytes:
    """Encrypt ``message`` with AES-256 with key ``key``."""
    assert len(message) == 16
    assert len(key) == 32

    m = _split(message)
    key_schedule = _key_schedule(_split(key))
    # add round key
    m = [a ^ b for a, b in zip(m, key_schedule[0:4])]
    for i in range(4, len(key_schedule), 4):
        # apply S-Box
        m = [_sub_word(w) for w in m]
        # apply ShiftRows
        m = _to_matrix(m)
        m = _shift_rows(m)
        # apply MixColumns
        if i + 4 < len(key_schedule):
            m = _mix_columns(m)
        m = _from_matrix(m)
        # add round key
        m = [a ^ b for a, b in zip(m, key_schedule[i:i + 4])]
    return _combine(m)


def aes_decrypt(message: bytes, key: bytes) -> bytes:
    """Decrypt ``message`` with AES-256 with key ``key``."""
    assert len(message) == 16
    assert len(key) == 32

    m = _split(message)
    key_schedule = _key_schedule(_split(key))
    for i in reversed(range(4, len(key_schedule), 4)):
        # add round key
        m = [a ^ b for a, b in zip(m, key_schedule[i:i + 4])]
        # apply InvMixColumns
        m = _to_matrix(m)
        if i + 4 < len(key_schedule):
            m = _inv_mix_columns(m)
        # apply InvShiftRows
        m = _inv_shift_rows(m)
        m = _from_matrix(m)
        # apply S-Box
        m = [_inv_sub_word(w) for w in m]
    # add round key
    m = [a ^ b for a, b in zip(m, key_schedule[:4])]
    return _combine(m)


class AES256(BlockCipher):
    """
    The AES-256 symmetric block cipher.
    """

    blocksize = 16
    keysize = 32

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypt data.
        """
        return aes_encrypt(data, key)

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        """
        Decrypt data.
        """
        return aes_decrypt(data, key)

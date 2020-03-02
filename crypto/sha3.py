"""
Implements the SHA-3 hash and extendenable output functions.

WARNING: These implementations are for educational purposes.
         DO NOT use them for real-world applications!

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import typing

from . import keccak
from . import padding
from . import sponge_crypto


KECCAK_F = keccak.KeccakF(6)


def _create_hash(blocksize: int,
                 result_bits: int) -> typing.Callable[[bytes], bytes]:
    """Create hash function based on Keccak-f."""
    blocksize = blocksize // 8
    result_bytes = result_bits // 8

    def f(msg: bytes) -> bytes:
        h = sponge_crypto.SpongeHash(KECCAK_F,
                                     blocksize,
                                     padding.add_10star1_padding)
        h.absorb(msg)
        h.final_absorb(b'\x02', 2)
        return h.squeeze(result_bytes)

    return f


def _create_shake(blocksize: int) -> typing.Callable[[bytes, int], bytes]:
    """Create extendable output function (XOF) based on Keccak-f."""
    blocksize = blocksize // 8

    def f(msg: bytes, result_bytes: int) -> bytes:
        h = sponge_crypto.SpongeHash(KECCAK_F,
                                     blocksize,
                                     padding.add_10star1_padding)
        h.absorb(msg)
        h.final_absorb(b'\x0F', 4)
        return h.squeeze(result_bytes)

    return f


sha_3_224 = _create_hash(1152, 224)
sha_3_256 = _create_hash(1088, 256)
sha_3_384 = _create_hash(832, 384)
sha_3_512 = _create_hash(576, 512)

shake128 = _create_shake(1344)
shake256 = _create_shake(1088)

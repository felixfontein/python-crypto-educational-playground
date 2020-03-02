"""
Implements the sponge-based hash function and the sponge-based AEAD cipher as
described in G. Bertoni, J. Daemen, M. Peeters, G. v. Assche: "The Keccak
Reference", 2011. Available at
https://keccak.team/files/Keccak-reference-3.0.pdf

WARNING: These implementations are for educational purposes.
         DO NOT use them for real-world applications!

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import typing

from .sponge import F, Sponge, DuplexSponge


class SpongeHash:
    """
    Provides a hash function given a sponge f function, parameters and a
    padding function.
    """

    def __init__(self,
                 f: F,
                 blocksize: int,
                 padding: typing.Callable[[bytes, int], bytes]):
        self._f = f
        self._sponge = Sponge(f, blocksize)
        self._blocksize = blocksize
        self._padding = padding
        self._buffer = b''
        self._absorbing = True

    def _process_buffer(self):
        last_index = 0
        for i in range(self._blocksize,
                       len(self._buffer) + 1,
                       self._blocksize):
            self._sponge.absorb(self._buffer[i - self._blocksize:i])
            last_index = i
        self._buffer = self._buffer[last_index:]

    def absorb(self, data: bytes):
        """Adds block of data. More data must be coming."""
        assert self._absorbing
        self._buffer += data
        if len(self._buffer) >= self._blocksize:
            self._process_buffer()

    def final_absorb(self, data: bytes, bitlength: int = None):
        """Adds a final block of data. No more data must be coming."""
        if bitlength is None:
            bitlength = len(data) * 8
        bitlength += len(self._buffer) * 8
        self._buffer += data
        self._buffer = self._padding(self._buffer, self._blocksize, bitlength)
        self._process_buffer()
        assert len(self._buffer) == 0
        self._absorbing = False

    def squeeze(self, number_of_bytes=None) -> bytes:
        """Squeezes a number of bytes out of the sponge.

        Must only be called after ``final_absorb()``."""
        assert not self._absorbing
        if number_of_bytes is None:
            number_of_bytes = self._blocksize
        result = []
        result_len = 0
        while result_len < number_of_bytes:
            result.append(self._sponge.squeeze())
            result_len += self._blocksize
        if result_len > number_of_bytes:
            result[-1] = result[-1][:-(result_len - number_of_bytes)]
        return b''.join(result)

    def clone(self) -> 'SpongeHash':
        """Create copy of this sponge-based hash."""
        result = SpongeHash(self._f, self._blocksize, self._padding)
        result._sponge = self._sponge.clone()


class SpongeAEAD:
    """
    Provides an Authenticated Encryption with Additional Data (AEAD) algorithm
    given a sponge f function, parameters and a padding function.
    """

    def __init__(self,
                 f: F,
                 sponge_blocksize: int,
                 cipher_blocksize: int,
                 tag_length: int,
                 padding: typing.Callable[[bytes, int], bytes]):
        assert cipher_blocksize < sponge_blocksize
        self._f = f
        self._sponge_blocksize = sponge_blocksize
        self._cipher_blocksize = cipher_blocksize
        self._tag_length = tag_length
        self._padding = padding

    def _split(self, data: bytes):
        result = []
        for i in range(0, len(data), self._cipher_blocksize):
            result.append(data[i:i + self._cipher_blocksize])
        if not result:
            result.append(b'')
        return result

    def encrypt_and_tag(self,
                        key: bytes,
                        header: bytes,
                        data: bytes) -> typing.Tuple[bytes, bytes]:
        """
        Encrypt and tag a ``header`` and ``data`` with a private ``key``.

        Returns a tuple ``(ciphertext, tag)``, where ``ciphertext`` is the
        encryption of ``data`` and where ``tag`` authenticates both ``header``
        and ``data``.
        """
        sponge = DuplexSponge(self._f, self._sponge_blocksize, self._padding)
        # Feed in key
        for block in self._split(key):
            sponge.duplex(block, 0)
        # Feed in header (except last block)
        header_blocks = self._split(header)
        for block in header_blocks[:-1]:
            sponge.duplex(block + b'\x00', 0, len(block) * 8 + 1)
        last = header_blocks[-1]
        # Encrypt data
        encryption = []
        for block in self._split(data):
            res = sponge.duplex(last + b'\x01', len(block), len(last) * 8 + 1)
            encryption.append(bytes(a ^ b for a, b in zip(block, res)))
            last = block
        # Compute tag
        tag = []
        tag_length = 0
        last_bitlength = len(last) * 8 + 1
        last += b'\x00'
        while tag_length < self._tag_length:
            b = min(self._cipher_blocksize, self._tag_length - tag_length)
            res = sponge.duplex(last, b, last_bitlength)
            tag.append(res)
            tag_length += len(res)
            last = b'\x00'
            last_bitlength = 1
        # Return result
        return b''.join(encryption), b''.join(tag)

    def decrypt_and_authenticate(self,
                                 key: bytes,
                                 header: bytes,
                                 encrypted_data: bytes,
                                 tag: bytes) -> typing.Tuple[bytes, bytes]:
        """
        Decrypted encrypted data ``encrypted_data`` and authenticate both
        data and ``header`` with private key ``key`` and tag ``tag``.

        Returns the cleartext data on success, and raises an exception in case
        the tag does not match.
        """
        sponge = DuplexSponge(self._f, self._sponge_blocksize, self._padding)
        # Feed in key
        for block in self._split(key):
            sponge.duplex(block, 0)
        # Feed in header (except last block)
        header_blocks = self._split(header)
        for block in header_blocks[:-1]:
            sponge.duplex(block + b'\x00', 0, len(block) * 8 + 1)
        last = header_blocks[-1]
        # Decrypt data
        decryption = []
        for block in self._split(encrypted_data):
            res = sponge.duplex(last + b'\x01', len(block), len(last) * 8 + 1)
            decrypted_block = bytes(a ^ b for a, b in zip(block, res))
            decryption.append(decrypted_block)
            last = decrypted_block
        # Compute tag
        computed_tag = []
        computed_tag_length = 0
        last_bitlength = len(last) * 8 + 1
        last += b'\x00'
        while computed_tag_length < self._tag_length:
            b = min(self._cipher_blocksize,
                    self._tag_length - computed_tag_length)
            res = sponge.duplex(last, b, last_bitlength)
            computed_tag.append(res)
            computed_tag_length += len(res)
            last = b'\x00'
            last_bitlength = 1
        # Validate tag and return result in case of success
        if tag != b''.join(computed_tag):
            raise ValueError('Tag does not match!')
        return b''.join(decryption)

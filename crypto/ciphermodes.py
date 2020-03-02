"""
Provides Block Cipher Modes.

WARNING: These implementations are for educational purposes.
         DO NOT use them for real-world applications!

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import typing

from .cipher import BlockCipher, BlockCipherMode


class ECB(BlockCipherMode):
    """
    Electronic Code Book (ECB) mode.
    https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)
    """

    def __init__(self, key: bytes):
        self._key = key

    def create_encryptor(self,
                         cipher: BlockCipher,
                         ) -> typing.Callable[[bytes], bytes]:
        """
        Create encryptor.
        """
        blocksize = cipher.blocksize
        assert len(self._key) == cipher.keysize

        def f(data: bytes):
            assert len(data) % blocksize == 0
            result = []
            for i in range(0, len(data), blocksize):
                # Encrypt every block the same way
                result.append(cipher.encrypt(
                    data[i:i + blocksize], self._key))
            return b''.join(result)

        return f

    def create_decryptor(self,
                         cipher: BlockCipher,
                         ) -> typing.Callable[[bytes], bytes]:
        """
        Create decryptor.
        """
        blocksize = cipher.blocksize
        assert len(self._key) == cipher.keysize

        def f(encrypted_data: bytes):
            assert len(encrypted_data) % blocksize == 0
            result = []
            for i in range(0, len(encrypted_data), blocksize):
                # Decrypt every block the same way
                result.append(cipher.decrypt(
                    encrypted_data[i:i + blocksize], self._key))
            return b''.join(result)

        return f


class CTR(BlockCipherMode):
    """
    Counter (CTR) mode.
    https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
    """

    def __init__(self, key: bytes, nonce: bytes):
        self._key = key
        self._nonce = nonce
        self._nonce_int = int.from_bytes(nonce, byteorder='big')

    def create_encryptor(self,
                         cipher: BlockCipher,
                         ) -> typing.Callable[[bytes], bytes]:
        """
        Create encryptor.
        """
        blocksize = cipher.blocksize
        assert len(self._nonce) == blocksize
        assert len(self._key) == cipher.keysize

        def f(data: bytes):
            result = []
            ctr = self._nonce_int
            for i in range(0, len(data), blocksize):
                # Create mask by encrypting the current counter value
                mask = cipher.encrypt(
                    ctr.to_bytes(blocksize, byteorder='big'),
                    self._key
                )
                # XOR mask with plaintext
                result.append(bytes(a ^ b for a, b in zip(
                    data[i:i + blocksize],
                    mask
                )))
                # Increase counter
                ctr = (ctr + 1) & ((1 << (8 * blocksize)) - 1)
            return b''.join(result)

        return f

    def create_decryptor(self,
                         cipher: BlockCipher,
                         ) -> typing.Callable[[bytes], bytes]:
        """
        Create decryptor.
        """
        return self.create_encryptor(cipher)


class CBC(BlockCipherMode):
    """
    Cipher Block Chaining (CBC) mode.
    https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
    """

    def __init__(self, key: bytes, iv: bytes):
        self._key = key
        self._iv = iv

    def create_encryptor(self,
                         cipher: BlockCipher,
                         ) -> typing.Callable[[bytes], bytes]:
        """
        Create encryptor.
        """
        blocksize = cipher.blocksize
        assert len(self._iv) == blocksize
        assert len(self._key) == cipher.keysize

        def f(data: bytes):
            assert len(data) % blocksize == 0
            result = []
            last = self._iv
            for i in range(0, len(data), blocksize):
                v = bytes([a ^ b for a, b in zip(
                    data[i:i + blocksize],
                    last
                )])
                last = cipher.encrypt(v, self._key)
                result.append(last)
            return b''.join(result)

        return f

    def create_decryptor(self,
                         cipher: BlockCipher,
                         ) -> typing.Callable[[bytes], bytes]:
        """
        Create decryptor.
        """
        blocksize = cipher.blocksize
        assert len(self._iv) == blocksize
        assert len(self._key) == cipher.keysize

        def f(encrypted_data: bytes):
            assert len(encrypted_data) % blocksize == 0
            result = []
            last = self._iv
            for i in range(0, len(encrypted_data), blocksize):
                old_last, last = last, encrypted_data[i:i + blocksize]
                result.append(bytes([a ^ b for a, b in zip(
                    cipher.decrypt(last, self._key), old_last)]))
            return b''.join(result)

        return f

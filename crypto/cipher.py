"""
Abstract cipher definitions.

WARNING: These implementations are for educational purposes.
         DO NOT use them for real-world applications!

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import abc
import typing

import six


@six.add_metaclass(abc.ABCMeta)
class BlockCipher:
    """
    Abstract interface for a cipher.
    """

    blocksize: int  # blocksize in bytes
    keysize: int    # keysize in bytes

    @abc.abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypt data.
        """

    @abc.abstractmethod
    def decrypt(self, data: bytes, key: bytes) -> bytes:
        """
        Decrypt data.
        """


@six.add_metaclass(abc.ABCMeta)
class BlockCipherMode:
    """
    Abstract interface for a cipher.
    """

    @abc.abstractmethod
    def create_encryptor(self,
                         cipher: BlockCipher,
                         ) -> typing.Callable[[bytes], bytes]:
        """
        Create encryptor.
        """

    @abc.abstractmethod
    def create_decryptor(self,
                         cipher: BlockCipher,
                         ) -> typing.Callable[[bytes], bytes]:
        """
        Create decryptor.
        """


@six.add_metaclass(abc.ABCMeta)
class Cipher:
    """
    Abstract interface for a cipher.
    """

    @abc.abstractmethod
    def encryptor(self) -> typing.Callable[[bytes], bytes]:
        """
        Create encryptor object.
        """

    @abc.abstractmethod
    def decryptor(self) -> typing.Callable[[bytes], bytes]:
        """
        Create decryptor object.
        """

    @staticmethod
    def from_block_cipher(cipher: BlockCipher,
                          mode: BlockCipherMode,
                          ) -> 'Cipher':
        """
        Create cipher from block cipher object and block cipher mode object.
        """
        return _BlockCipher(cipher, mode)


class _BlockCipher(Cipher):
    """
    Abstract interface for a cipher.
    """

    def __init__(self,
                 cipher: BlockCipher,
                 mode: BlockCipherMode):
        self._cipher = cipher
        self._mode = mode

    def encryptor(self) -> typing.Callable[[bytes], bytes]:
        """
        Create encryptor object.
        """
        return self._mode.create_encryptor(self._cipher)

    def decryptor(self) -> typing.Callable[[bytes], bytes]:
        """
        Create decryptor object.
        """
        return self._mode.create_decryptor(self._cipher)

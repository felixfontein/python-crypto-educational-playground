"""
Implements the sponge construction and the duplex sponge construction as
described in G. Bertoni, J. Daemen, M. Peeters, G. v. Assche: "The Keccak
Reference", 2011. Available at
https://keccak.team/files/Keccak-reference-3.0.pdf

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
class State:
    """
    Abstract interface for the state of a sponge f function.
    """

    @abc.abstractmethod
    def from_bytes(self, value: bytes):
        """Incorporate bytes into state via XOR.

        Must not exceed size of state."""

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        """Convert state into byte string of length self.b_bytes."""

    @abc.abstractmethod
    def clone(self) -> 'State':
        """Create copy of this state."""


@six.add_metaclass(abc.ABCMeta)
class F:
    """
    Abstract interface for a sponge f function.
    """

    @abc.abstractmethod
    def new_state(self) -> State:
        """Create a new zeroed state object."""

    @abc.abstractmethod
    def __call__(self, state: State):
        """Apply function to the given state.

        The state must always have been created by this class'
        ``new_state()`` function.
        """


class Sponge:
    """
    Provides a sponge function given a sponge f function and a blocksize.
    """

    def __init__(self, f: F, blocksize: int):
        self._f = f
        self._state = f.new_state()
        self._blocksize = blocksize

    def absorb(self, data: bytes):
        """Adds block of data and applies f."""
        assert len(data) <= self._blocksize
        self._state.from_bytes(data)
        self._f(self._state)

    def squeeze(self) -> bytes:
        """Squeeze a block out of the sponge."""
        result = self._state.to_bytes()[:self._blocksize]
        self._f(self._state)
        return result

    def clone(self) -> 'Sponge':
        """Create copy of this sponge."""
        result = Sponge(self._f, self._blocksize)
        result._state = self._state.clone()
        return result


class DuplexSponge:
    """
    Provides a duplex sponge function given a sponge f function, blocksize and
    a padding function.
    """

    def __init__(self,
                 f: F,
                 blocksize: int,
                 padding: typing.Callable[[bytes, int], bytes]):
        self._f = f
        self._state = f.new_state()
        self._blocksize = blocksize
        self._padding = padding

    def duplex(self,
               data: bytes,
               result_bytes: int = None,
               input_bitlength: int = None):
        """Adds a block of data and retrieves a number of bytes.

        The data block must be small enough that padding(data) fits into
        blocksize. Also result_bytes must not exceed blocksize.
        """
        if result_bytes is None:
            result_bytes = self._blocksize
        else:
            assert result_bytes <= self._blocksize
        # Incorporate data
        data = self._padding(data, self._blocksize, input_bitlength)
        assert len(data) <= self._blocksize
        self._state.from_bytes(data)
        # Apply f
        self._f(self._state)
        # Retrieve data
        if result_bytes > 0:
            return self._state.to_bytes()[:result_bytes]
        return b''

    def clone(self) -> 'DuplexSponge':
        """Create copy of this duplex sponge."""
        result = DuplexSponge(self._f, self._blocksize, self._padding)
        result._state = self._state.clone()
        return result

"""
Implements the Keccak-f function as described in G. Bertoni, J. Daemen,
M. Peeters, G. v. Assche: "The Keccak Reference", 2011. Available at
https://keccak.team/files/Keccak-reference-3.0.pdf

WARNING: These implementations are for educational purposes.
         DO NOT use them for real-world applications!

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

from typing import List

from .utils import ROL

from .sponge import State, F


class KeccakFState(State):
    """Represents the Keccak-f state split up into lanes."""

    _lanes: List[List[int]]

    def __init__(self, ell: int = 6):
        assert ell >= 3  # we want 2 ** ell to be divisible by 8
        self.ell = ell
        self.b = 25 * 2 ** ell
        self.b_bytes = (self.b + 7) // 8
        self._lanes = [[0] * 5 for _ in range(5)]

    def _add_to_state(self, state: bytes):
        """Add bytes to state. Expects exactly self.b_bytes bytes."""
        lane_length = 2 ** (self.ell - 3)
        i = 0
        for y in range(5):
            for x in range(5):
                # We now have i == (5 * y + x) * lane_length
                v = int.from_bytes(state[i:i + lane_length],
                                   byteorder='little')
                self._lanes[x][y] ^= v
                i += lane_length

    def from_bytes(self, value: bytes):
        """Incorporate bytes into state.

        Can be between 0 and ``self.b_bytes`` bytes long."""
        if len(value) > self.b_bytes:
            raise ValueError(
                'Cannot initialize Keccak-f state with more '
                'than {0} bytes'.format(self.b_bytes)
            )
        if len(value) < self.b_bytes:
            value = value + b'\x00' * (self.b_bytes - len(value))
        self._add_to_state(value)

    def to_bytes(self) -> bytes:
        """Converts state into byte string of length self.b_bytes."""
        result = []
        lane_length = 2 ** (self.ell - 3)
        for y in range(5):
            for x in range(5):
                result.append(self._lanes[x][y].to_bytes(
                    lane_length, byteorder='little'))
        return b''.join(result)

    def clone(self) -> 'KeccakFState':
        result = KeccakFState(self.ell)
        result._lanes = [list(lanes) for lanes in self._lanes]
        return result


def compute_t_matrix():
    """Precompute values for t for Keccak-f's rho step."""
    def mul(a, b, m):
        return [
            [(a[0][0] * b[0][0] + a[0][1] * b[1][0]) % m,
             (a[0][0] * b[0][1] + a[0][1] * b[1][1]) % m],
            [(a[1][0] * b[0][0] + a[1][1] * b[1][0]) % m,
             (a[1][0] * b[0][1] + a[1][1] * b[1][1]) % m],
        ]

    result = [[-1] * 5 for _ in range(5)]
    A = [[0, 1], [2, 3]]
    B = [[1, 0], [0, 1]]
    for t in range(24):
        result[B[0][0]][B[1][0]] = t
        B = mul(B, A, 5)
    return result


def compute_rc(count):
    """Precompute round constant LFSR values for Keccak-f's iota step."""
    result = [1]
    intermediate = [1, 0, 0, 0, 0, 0, 0, 0]
    for _ in range(count):
        last_bit = intermediate[-1]
        intermediate = [0] + intermediate[:-1]
        if last_bit:
            intermediate[0] ^= 1
            intermediate[4] ^= 1
            intermediate[5] ^= 1
            intermediate[6] ^= 1
        result.append(intermediate[0])
    return result


class KeccakF(F):
    """Allow to evaluate Keccak-f."""
    def __init__(self, ell: int = 6):
        assert ell >= 3  # we want 2 ** ell to be divisible by 8
        self.ell = ell
        self._2ell = 2 ** ell
        self._2ell_mask = self._2ell - 1
        self.b = 25 * self._2ell
        self.b_bytes = (self.b + 7) // 8
        self.n = 12 + 2 * ell
        self._rc = compute_rc(self.ell + 7 * self.n + 1)
        self._t = compute_t_matrix()

    def new_state(self) -> KeccakFState:
        """Create a new zeroed state object."""
        return KeccakFState(self.ell)

    def _theta(self, lanes: List[List[int]]):
        result = [[None] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                v = lanes[x][y]
                for yy in range(5):
                    v ^= lanes[(x + 4) % 5][yy]
                    v ^= ROL(lanes[(x + 1) % 5][yy], 1, self._2ell)
                result[x][y] = v
        return result

    def _rho(self, lanes: List[List[int]]):
        result = [[None] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                t = self._t[x][y]
                dt = ((t + 1) * (t + 2) // 2) & self._2ell_mask
                v = lanes[x][y]
                if dt != 0:
                    v = ROL(v, dt, self._2ell)
                result[x][y] = v
        return result

    @staticmethod
    def _pi(lanes: List[List[int]]):
        result = [[None] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                result[x][y] = lanes[(x + 3 * y) % 5][x]
        return result

    @staticmethod
    def _chi(lanes: List[List[int]]):
        result = [[None] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                v1 = lanes[(x + 1) % 5][y] & lanes[(x + 2) % 5][y]
                v2 = lanes[(x + 2) % 5][y]
                result[x][y] = lanes[x][y] ^ v1 ^ v2
        return result

    def _iota(self, lanes: List[List[int]], i):
        for j in range(self.ell + 1):
            if self._rc[j + 7 * i]:
                bit_idx = (1 << j) - 1
                lanes[0][0] ^= 1 << bit_idx
        return lanes

    def __call__(self, state: KeccakFState):
        """Apply function to the given state."""
        assert self.b == state.b
        lanes = state._lanes
        for i in range(self.n):
            lanes = self._theta(lanes)
            lanes = self._rho(lanes)
            lanes = self._pi(lanes)
            lanes = self._chi(lanes)
            lanes = self._iota(lanes, i)
        state._lanes = lanes

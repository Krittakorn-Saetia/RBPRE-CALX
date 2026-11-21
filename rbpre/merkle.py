"""rbpre.merkle: the patient-specific Merkle structure M_PID* (Eq. 78, 80).

SHA-256 binary Merkle tree with domain separation between leaves (0x00) and
inner nodes (0x01), as in RFC 6962. On a level with an odd number of nodes the
last node is promoted unchanged, so no leaf is ever duplicated.

    RootP = MerkleRoot([FlagID_1, ..., FlagID_n])
    MerkleVerify(FlagID_i, proof_i, RootP) = 1
"""

from __future__ import annotations

import hashlib


def _leaf(x: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + x).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


EMPTY_ROOT = hashlib.sha256(b"").digest()


class MerkleTree:
    def __init__(self, leaves: list[bytes]):
        self.leaves = list(leaves)
        self._levels: list[list[bytes]] = []
        self._build()

    def _build(self) -> None:
        level = [_leaf(x) for x in self.leaves]
        self._levels = [level]
        while len(level) > 1:
            nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
            if len(level) % 2:
                nxt.append(level[-1])
            level = nxt
            self._levels.append(level)

    def append(self, leaf: bytes) -> None:
        self.leaves.append(leaf)
        self._build()

    @property
    def root(self) -> bytes:
        return self._levels[-1][0] if self.leaves else EMPTY_ROOT

    def proof(self, index: int) -> list[tuple[int, bytes]]:
        """Audit path: list of (side, sibling); side 0 = sibling on the left."""
        if not 0 <= index < len(self.leaves):
            raise IndexError(index)
        path, i = [], index
        for level in self._levels[:-1]:
            sib = i ^ 1
            if sib < len(level):
                path.append((0 if sib < i else 1, level[sib]))
            i //= 2
        return path


def verify(leaf: bytes, proof: list[tuple[int, bytes]], root: bytes) -> bool:
    h = _leaf(leaf)
    for side, sib in proof:
        h = _node(sib, h) if side == 0 else _node(h, sib)
    return h == root

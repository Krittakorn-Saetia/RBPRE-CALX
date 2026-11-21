"""rbpre.policy: monotone AND/OR policies for the CP-ABPRE of Ibraimi et al.

Syntax: attributes joined with AND / OR (case-insensitive) and parentheses,
e.g. "hosp:HA AND (role:physician OR role:nurse)". An attribute is any run of
letters, digits and the characters _ : . - @ /.

The scheme of [41] shares the encryption exponent additively over the access
tree (AND: random shares that sum to the parent value; OR: every child gets the
parent value), and indexes key components by attribute only. Each attribute may
therefore appear at most once per policy; parse() rejects repeats.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional, Union

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_:.\-@/]+)")


@dataclass(frozen=True)
class Leaf:
    attr: str


@dataclass(frozen=True)
class Gate:
    op: str  # "AND" or "OR"
    children: tuple["Node", ...]


Node = Union[Leaf, Gate]


class PolicyError(ValueError):
    pass


def _tokenize(s: str) -> list[str]:
    pos, out = 0, []
    s = s.strip()
    while pos < len(s):
        m = _TOKEN.match(s, pos)
        if not m:
            raise PolicyError(f"bad policy syntax near {s[pos:pos + 20]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


def parse(policy: str) -> Node:
    """Parse a policy string; AND binds tighter than OR."""
    toks = _tokenize(policy)
    if not toks:
        raise PolicyError("empty policy")
    i = 0

    def peek():
        return toks[i] if i < len(toks) else None

    def take():
        nonlocal i
        t = toks[i]
        i += 1
        return t

    def is_op(t, op):
        return t is not None and t.upper() == op

    def p_or() -> Node:
        kids = [p_and()]
        while is_op(peek(), "OR"):
            take()
            kids.append(p_and())
        return kids[0] if len(kids) == 1 else Gate("OR", tuple(kids))

    def p_and() -> Node:
        kids = [p_atom()]
        while is_op(peek(), "AND"):
            take()
            kids.append(p_atom())
        return kids[0] if len(kids) == 1 else Gate("AND", tuple(kids))

    def p_atom() -> Node:
        t = peek()
        if t is None:
            raise PolicyError("unexpected end of policy")
        if t == "(":
            take()
            n = p_or()
            if peek() != ")":
                raise PolicyError("missing ')'")
            take()
            return n
        if t == ")" or t.upper() in ("AND", "OR"):
            raise PolicyError(f"unexpected token {t!r}")
        return Leaf(take())

    node = p_or()
    if i != len(toks):
        raise PolicyError(f"trailing tokens: {toks[i:]}")
    attrs = attributes(node)
    if len(attrs) != len(set(attrs)):
        dup = sorted({a for a in attrs if attrs.count(a) > 1})
        raise PolicyError(f"attribute repeated in policy: {dup}")
    return node


def attributes(node: Node) -> list[str]:
    if isinstance(node, Leaf):
        return [node.attr]
    out: list[str] = []
    for c in node.children:
        out += attributes(c)
    return out


def canonical(node: Node) -> str:
    """Canonical text of a parsed policy (used for H(P))."""
    if isinstance(node, Leaf):
        return node.attr
    return "(" + f" {node.op} ".join(canonical(c) for c in node.children) + ")"


def canon(policy: str) -> str:
    return canonical(parse(policy))


def share(node: Node, secret, rand: Callable[[], object]) -> dict[str, object]:
    """Additive sharing of `secret` over the tree (Benaloh-Leichter style).

    `rand()` returns a fresh random exponent; arithmetic is done on the
    exponent type (Charm ZR elements).
    """
    out: dict[str, object] = {}

    def go(n: Node, v):
        if isinstance(n, Leaf):
            out[n.attr] = v
            return
        if n.op == "OR":
            for c in n.children:
                go(c, v)
            return
        acc = None
        for c in n.children[:-1]:
            r = rand()
            go(c, r)
            acc = r if acc is None else acc + r
        go(n.children[-1], v - acc)

    go(node, secret)
    return out


def satisfying_set(node: Node, attrs) -> Optional[list[str]]:
    """A minimal set of policy leaves covered by `attrs`, or None.

    The shares of the returned leaves sum to the root secret. For an OR gate the
    child with the smallest satisfying set is chosen.
    """
    have = set(attrs)

    def go(n: Node) -> Optional[list[str]]:
        if isinstance(n, Leaf):
            return [n.attr] if n.attr in have else None
        if n.op == "AND":
            out: list[str] = []
            for c in n.children:
                s = go(c)
                if s is None:
                    return None
                out += s
            return out
        best = None
        for c in n.children:
            s = go(c)
            if s is not None and (best is None or len(s) < len(best)):
                best = s
        return best

    return go(node)

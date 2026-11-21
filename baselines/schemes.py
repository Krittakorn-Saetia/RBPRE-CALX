"""The compared schemes [25], [27], [31] and the conventional PRE pipeline.

Per-operation costs follow Table IV of the paper:

                     [25]                        [27]                       [31]
  Authentication     T_sm + T_p + T_H + T_sym    T_P + m T_E + m T_M         T_IBS^sign + T_IBS^ver
                     + T_add                                                 + T_H + T_B^qry
  Transformation     n/a (symmetric re-wrap      T_P + t T_E + t T_M         T_IBS^ver + T_H + T_B^qry
                     as a reference)             per record                  per record
  Verification       n/a                         T_P + T_H per record        T_IBS^ver + T_H + T_B^qry
  Traceability       T_H + anchor per event      T_B^upd + T_con per event   T_B^upd + T_con per event

Longitudinal retrieval is not supported by any of the three (Table IV). For
the retrieval experiments each locates the patient's records with a repository
scan and then runs its own per-record validation: an access-token check for
[25], attribute-based reconstruction (T_P + t T_E + t T_M) for [27], and
per-domain chain synchronization plus per-record IBS verification for [31].

Group elements that stand for per-record ciphertext components and
signatures are drawn from a pre-generated pool, so the timed operations are
real but setup cost stays outside the measurement.
"""

from __future__ import annotations

import json
import os
import time

from baselines.common import IndexEntry, Prims, per_event_invoke, scan
from rbpre import rbabpre as rb
from rbpre.abpre import CPABPRE
from rbpre.encoding import H

POOL = 64


class Wang25:
    name = "[25]"

    def __init__(self, prims: Prims, ledger=None):
        self.p, self.ledger = prims, ledger
        self.ta_sk = prims.ec_scalar()
        self.ta_pk = prims.T_sm(prims.P, self.ta_sk)
        self.tk = os.urandom(32)
        self.tid = os.urandom(32)
        self.f = prims.T_p(b"c0")
        self.wraps = [prims.T_sym_enc(os.urandom(32)) for _ in range(POOL)]

    def auth_request(self) -> bool:
        """Usage-limited cross-domain token request and verification."""
        p = self.p
        chal = os.urandom(16)
        f_new = p.T_p(chal)                                                    # T_p
        u = p.ec_scalar()
        U = p.T_sm(p.P, u)                                                     # T_sm
        K = p.T_add(U, self.ta_pk)                                             # T_add
        nonce, t2 = os.urandom(16), str(time.time()).encode()
        atk = p.T_H(self.tid, nonce, f_new, self.f, self.tk, t2)               # T_H
        msg = p.T_sym_enc(f_new + atk, p.T_H(str(K).encode()))                # T_sym
        # TA side: decrypt and recompute the authentication code
        body = p.T_sym_dec(msg, p.T_H(str(K).encode()))
        return body[32:] == p.T_H(self.tid, nonce, body[:32], self.f, self.tk, t2)

    def retrieve(self, index: list[IndexEntry], owner: bytes, subset: set | None = None):
        found = scan(index, owner, self.p)
        work = [e for e in found if subset is None or e.rid in subset]
        for e in work:  # access-token validation per record
            self.p.T_H(self.tk, e.rid.encode())
        return work

    def transform(self, records: list[IndexEntry]) -> None:
        """Reference only: symmetric re-wrap of each data key (no PRE)."""
        for i, _ in enumerate(records):
            key = self.p.T_sym_dec(self.wraps[i % POOL])
            self.p.T_sym_enc(key)

    def anchor(self, n_events: int, concurrency: int) -> None:
        pay = [json.dumps([self.p.T_H(os.urandom(16)).hex()]) for _ in range(n_events)]
        per_event_invoke(self.ledger, "AnchorShares", pay, concurrency)

    def revoke(self) -> None:
        """Blacklisting at the trusted authority: T_H."""
        self.blacklist = getattr(self, "blacklist", set())
        self.blacklist.add(self.p.T_H(self.tid, os.urandom(8)))


class Yan27:
    name = "[27]"

    def __init__(self, prims: Prims, ledger=None, m: int = 10, t: int = 3):
        self.p, self.ledger, self.m, self.t = prims, ledger, m, t
        self.attr = [(prims.g1(), prims.zr()) for _ in range(m)]
        self.comp = [(prims.g1(), prims.g1(), [prims.zr() for _ in range(t)]) for _ in range(POOL)]

    def auth_request(self) -> None:
        """Attribute-based authorization: T_P + m T_E + m T_M."""
        p = self.p
        acc = p.T_P(p.g, p.h)
        x = p.g
        for a, r in self.attr:
            x = p.T_M(x, p.T_E(a, r))
        return acc, x

    def _reconstruct(self, i: int):
        """Threshold reconstruction of one record: T_P + t T_E + t T_M."""
        p = self.p
        c1, c2, lag = self.comp[i % POOL]
        z = p.T_P(c1, c2)
        acc = c1
        for lam in lag:
            acc = p.T_M(acc, p.T_E(c2, lam))
        return z, acc

    def retrieve(self, index, owner, subset=None):
        found = scan(index, owner, self.p)
        work = [e for e in found if subset is None or e.rid in subset]
        for i, _ in enumerate(work):
            self._reconstruct(i)
        return work

    def transform(self, records) -> None:
        for i, _ in enumerate(records):
            self._reconstruct(i)

    def verify(self, records) -> None:
        """Ciphertext and share verification: T_P + T_H per record."""
        p = self.p
        for i, e in enumerate(records):
            c1, c2, _ = self.comp[i % POOL]
            p.T_P(c1, c2)
            p.T_H(e.rid.encode())

    def policy_update(self, records) -> None:
        """Delegation / policy update (Table IV): every affected ciphertext is
        re-encrypted under the new policy, T_P + (m+1) T_E + m T_M per record."""
        p = self.p
        for i, _ in enumerate(records):
            c1, c2, _ = self.comp[i % POOL]
            p.T_P(c1, c2)
            x = c1
            for a, r in self.attr:
                x = p.T_M(x, p.T_E(a, r))
            p.T_E(c2, self.attr[0][1])

    def anchor(self, n_events: int, concurrency: int) -> None:
        """Distributed update with consensus per sharing event."""
        pay = [json.dumps([self.p.T_H(os.urandom(16)).hex()]) for _ in range(n_events)]
        per_event_invoke(self.ledger, "AnchorShares", pay, concurrency)


class Luo31:
    name = "[31]"

    def __init__(self, prims: Prims, ledger=None):
        self.p, self.ledger = prims, ledger
        self.dev_pk, self.dev_sk = prims.ibs_keygen("device@src")
        self.rec_pk, rec_sk = prims.ibs_keygen("domain@src")
        self.sigs = [(f"rec{i}", prims.T_IBS_sign(rec_sk, f"rec{i}")) for i in range(POOL)]
        self.did = None

    def bind(self, did: str) -> None:
        """A registered DID whose state the scheme queries on chain."""
        self.did = did

    def _query(self, n_domains: int = 1) -> None:
        for _ in range(n_domains):
            self.ledger.get_state({"did": [self.did]})                          # T_B^qry

    def auth_request(self) -> bool:
        p = self.p
        msg = "req|" + os.urandom(8).hex()
        sig = p.T_IBS_sign(self.dev_sk, msg)                                    # T_IBS^sign
        ok = p.T_IBS_ver(self.dev_pk, msg, sig)                                 # T_IBS^ver
        p.T_H(msg.encode())                                                     # T_H
        self._query()                                                           # T_B^qry
        return ok

    def _per_record(self, records) -> None:
        p = self.p
        for i, e in enumerate(records):
            m, s = self.sigs[i % POOL]
            p.T_IBS_ver(self.rec_pk, m, s)                                      # T_IBS^ver
            p.T_H(e.rid.encode())                                               # T_H

    def retrieve(self, index, owner, subset=None):
        found = scan(index, owner, self.p)
        work = [e for e in found if subset is None or e.rid in subset]
        self._query(len({e.hosp for e in work}))   # one chain synchronization per domain
        self._per_record(work)
        return work

    def transform(self, records) -> None:
        self._query(len({e.hosp for e in records}))
        self._per_record(records)

    def verify(self, records) -> None:
        self._query(len({e.hosp for e in records}))
        self._per_record(records)

    def anchor(self, n_events: int, concurrency: int) -> None:
        pay = [json.dumps([self.p.T_H(os.urandom(16)).hex()]) for _ in range(n_events)]
        per_event_invoke(self.ledger, "AnchorShares", pay, concurrency)

    def revoke(self) -> None:
        """Domain/identity revocation: one state update with consensus (T_B^upd + T_con)."""
        self.ledger.anchor_shares([self.p.T_H(b"revoke", os.urandom(16)).hex()])


class PlainPRE:
    """Conventional CP-ABPRE sharing over the same construction [41]: the
    patient's records are found by scanning, every record is transformed, and
    a fresh re-encryption key is generated per record (no context reuse)."""

    name = "PRE"

    def __init__(self, scheme: CPABPRE, kms: rb.KMS, prims: Prims, ledger=None):
        self.s, self.kms, self.p, self.ledger = scheme, kms, prims, ledger

    def retrieve(self, index, owner, subset=None):
        found = scan(index, owner, self.p)
        return [e for e in found if subset is None or e.rid in subset]

    def transform(self, items: list[dict], recipient_pk: bytes, p_b: str, chi) -> list[dict]:
        """items: dicts with hosp and ct_k (deserialized CP-ABPRE ciphertext)."""
        out = []
        for c in items:
            rk = self.kms.rekeygen(c["hosp"], c["ct_k"]["policy"], p_b, recipient_pk, chi)
            out.append(rb.reencrypt(self.s, self.kms.pp, self.kms.pk_kms, c["ct_k"], rk, chi))
        return out

    def verify(self, items: list[dict]) -> int:
        """Per-record ciphertext-record binding against the commitment on chain
        (Eq. 47-48), without linkage or Merkle evidence. items: dicts with rid,
        ct = (CT_m, CT_k bytes) and open (the record opening)."""
        st, _, _ = self.ledger.get_state({"rec": [c["rid"] for c in items]})
        ok = 0
        for c in items:
            op = c["open"]
            com = H(bytes.fromhex(c["rid"]), op["phi"], op["com_c"], op["e"], H(*c["ct"])).hex()
            ok += st["rec"].get(c["rid"]) == com
        return ok

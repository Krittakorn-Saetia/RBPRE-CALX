"""The compared schemes [25], [27], [31] and the conventional PRE pipeline.

Each scheme runs the operations its own paper specifies (checked against the
papers in November 2026; see EXPERIMENTS.md):

  [25] Wang et al., UAV cross-domain authentication (TNSE 2026), Table V:
       requester 2 T_sm + 8 T_h, server (TA) 1 T_sm + 10 T_h.
  [27] Yan et al., MediCrypt-DDT threshold ABE (IoT-J 2026), Table II and
       Sec. IV, on its curve MNT159: Encrypt P + (s+3)E + 2mM, Decrypt 2P + nE,
       ValidCT 2P, ShareDecrypt 1P, ShareVerify 2P + (s+1)E + sM.
  [31] Luo et al., cross-domain authentication (IoT-J 2025), Sec. V-B and
       Fig. 3: the device computes nothing; the source domain's server signs
       the request, the target domain's server verifies it (querying the chain
       only for an unknown sender), signs the response, and the source server
       verifies it: 2 T_IBS^sign + 2 T_IBS^ver per exchange.

None of the three supports longitudinal retrieval or proxy re-encryption.
Where an experiment needs an operation a scheme does
not have, the closest operation of that scheme stands in, and the experiment
documentation says which:
  retrieval (Exp 2)       [25] access-token hash per record; [27] Decrypt per
                          record; [31] per-domain chain sync + IBS verification
  transformation (Exp 3)  [25] symmetric re-wrap (reference only); [27] Decrypt
                          per record; [31] per-domain chain sync + IBS verification
  verification (Exp 4)    [27] ValidCT per record; [31] as above
  authorization (Exp 1)   [27] ShareDecrypt (requester) + ShareVerify (verifier)
  policy update           [27] re-encryption (Encrypt) of every affected record

Group elements that stand for per-record ciphertext components and
signatures are drawn from a pre-generated pool, so the timed operations are
real but setup cost stays outside the measurement.
"""

from __future__ import annotations

import json
import os
import time
import warnings

from charm.toolbox.pairinggroup import G1, G2, GT, ZR, PairingGroup, pair

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
        """Cross-domain authentication ([25] Table V): 3 T_sm + 18 T_h in all."""
        return self.auth_server(self.auth_client())

    @staticmethod
    def _chain(p, kb: bytes, nonce: bytes, t: bytes, tid: bytes, tk: bytes) -> bytes:
        """7 hashes: temporary identity, token and authenticator chain."""
        h = p.T_H(tid, nonce, t)
        for i in range(5):
            h = p.T_H(h, kb, bytes([i]))
        return p.T_H(h, tk)

    def auth_client(self):
        """UAV side: 2 T_sm + 8 T_h (key agreement with the TA, token and authenticator)."""
        p = self.p
        u = p.ec_scalar()
        U = p.T_sm(p.P, u)                                                     # T_sm
        K = p.T_sm(self.ta_pk, u)                                              # T_sm
        nonce, t = os.urandom(16), str(time.time()).encode()
        kb = str(K).encode()
        mac = self._chain(p, kb, nonce, t, self.tid, self.tk)                  # 7 T_h
        p.T_H(b"ssk", kb, mac)                                                 # T_h, session key
        return U, nonce, t, mac

    def auth_server(self, req) -> bool:
        """Server side: 1 T_sm + 10 T_h (same key, recomputed authenticator, token update)."""
        p = self.p
        U, nonce, t, mac = req
        K = p.T_sm(U, self.ta_sk)                                              # T_sm
        kb = str(K).encode()
        ok = self._chain(p, kb, nonce, t, self.tid, self.tk) == mac             # 7 T_h
        p.T_H(b"ssk", kb, mac)                                                 # T_h, session key
        p.T_H(b"token", kb, nonce)                                             # T_h, token update
        p.T_H(b"tid", self.tid, nonce)                                         # T_h, new temporary id
        return ok

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
    """MediCrypt-DDT [27]: distributed dynamic threshold ABE on MNT159 (its
    curve; G1 x G2 -> GT). s bounds the attributes of the ciphertext set S, m is
    the size of the encryption attribute set and n of the key attribute set; the
    attribute threshold t is a parameter of the scheme that its cost formulas
    do not depend on. The exponentiations E of Table II are taken in G1, the
    cheapest group of MNT159: [27] reports a constant encryption time of about
    3 ms, which G2 exponentiations (about 3 ms each on MNT159) could not give."""

    name = "[27]"

    def __init__(self, prims: Prims, ledger=None, m: int = 10, t: int = 3, s: int | None = None,
                 n: int | None = None, curve: str = "MNT159"):
        self.p, self.ledger, self.m, self.t = prims, ledger, m, t
        self.s, self.n = s or m, n or m
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            self.grp = grp = PairingGroup(curve)
        self.g, self.h = grp.random(G1), grp.random(G2)
        self.hj = [grp.random(G1) for _ in range(max(self.s, self.n) + 1)]   # public powers of gamma
        self.coef = [grp.random(ZR) for _ in range(max(self.s, self.n) + 1)]
        self.vk = grp.random(ZR)
        # per-record ciphertexts (C1 in G1, C2 in G2), user secret keys (G1), GT values
        self.ct = [(grp.random(G1), grp.random(G2)) for _ in range(POOL)]
        self.ct2 = [(grp.random(G1), grp.random(G2)) for _ in range(POOL)]
        self.usk = [grp.random(G1) for _ in range(POOL)]
        self.u = grp.random(GT)

    def _poly_in_exponent(self, k: int):
        """The exponent polynomial from k public powers: k exponentiations (G1)."""
        acc = self.hj[0] ** self.coef[0]
        for j in range(1, k):
            acc = acc * (self.hj[j] ** self.coef[j])
        return acc

    # ---- the paper's algorithms (costs of Table II / Sec. IV)
    def encrypt(self, i: int = 0):
        """Encrypt: P + (s+3)E + 2mM."""
        grp, kappa = self.grp, self.coef[0]
        k = pair(self.g, self.h) ** kappa                                 # P + E (GT)
        c1 = self.g ** kappa                                              # E (G1)
        c2 = self._poly_in_exponent(self.s + 1)                           # (s+1) E (G1)
        acc = k
        for j in range(2 * self.m):                                       # 2m M
            acc = acc * self.u
        return c1, c2, acc

    def decrypt(self, i: int):
        """Decrypt (Combine and recover K): 2P + nE."""
        c1, c2 = self.ct[i % POOL]
        hp = self._poly_in_exponent(self.n)                               # n E (G1)
        return pair(hp, c2) * pair(self.usk[i % POOL], c2)                # 2P

    def valid_ct(self, i: int) -> bool:
        """ValidCT: e(C1, C2) =? e(C1', C2'), 2P."""
        (a1, a2), (b1, b2) = self.ct[i % POOL], self.ct2[i % POOL]
        return pair(a1, a2) == pair(b1, b2)

    def share_decrypt(self, i: int = 0):
        """ShareDecrypt: theta_k = e(usk_k, C2), 1P."""
        return pair(self.usk[i % POOL], self.ct[i % POOL][1])

    def share_verify(self, theta, i: int = 0) -> bool:
        """ShareVerify: e(g, C2) =? e(C1, h^{P_k(gamma)})^-1 * u^vk, 2P + (s+1)E + sM."""
        c1, c2 = self.ct[i % POOL]
        lhs = pair(self.g, c2)                                            # P
        hp = self._poly_in_exponent(self.s)                               # s E + s M (G1)
        rhs = pair(hp, c2) * (self.u ** self.vk)                          # P + E (GT)
        return lhs == rhs and theta is not None

    # ---- the experiments' operations
    def auth_request(self) -> bool:
        return self.auth_server(self.auth_client())

    def auth_client(self):
        """Requester: its decryption share (ShareDecrypt), 1P. [27] has no
        authentication protocol; share verification is the access check."""
        return self.share_decrypt()

    def auth_server(self, theta) -> bool:
        """Verifier: ShareVerify, 2P + (s+1)E + sM."""
        return self.share_verify(theta)

    def retrieve(self, index, owner, subset=None):
        found = scan(index, owner, self.p)
        work = [e for e in found if subset is None or e.rid in subset]
        for i, _ in enumerate(work):
            self.decrypt(i)
        return work

    def transform(self, records) -> None:
        """No re-encryption in [27]: recovering each record for the recipient (Decrypt)."""
        for i, _ in enumerate(records):
            self.decrypt(i)

    def verify(self, records) -> None:
        """ValidCT per record, plus the record hash."""
        for i, e in enumerate(records):
            self.valid_ct(i)
            self.p.T_H(e.rid.encode())

    def policy_update(self, records) -> None:
        """Policy update: every affected ciphertext is encrypted again under the
        new policy, P + (s+3)E + 2mM per record."""
        for i, _ in enumerate(records):
            self.encrypt(i)

    def anchor(self, n_events: int, concurrency: int) -> None:
        """Distributed update with consensus per sharing event."""
        pay = [json.dumps([self.p.T_H(os.urandom(16)).hex()]) for _ in range(n_events)]
        per_event_invoke(self.ledger, "AnchorShares", pay, concurrency)


class Luo31:
    name = "[31]"

    def __init__(self, prims: Prims, ledger=None):
        self.p, self.ledger = prims, ledger
        self.ms_a_pk, self.ms_a_sk = prims.ibs_keygen("MS@domainA")
        self.ms_b_pk, self.ms_b_sk = prims.ibs_keygen("MS@domainB")
        self.rec_pk, rec_sk = prims.ibs_keygen("domain@src")
        self.sigs = [(f"rec{i}", prims.T_IBS_sign(rec_sk, f"rec{i}")) for i in range(POOL)]
        self.did = None
        self.known: set = set()   # sender IDs already in MS_b's local database

    def bind(self, did: str) -> None:
        """A registered DID whose state the scheme queries on chain."""
        self.did = did

    def _query(self, n_domains: int = 1) -> None:
        for _ in range(n_domains):
            self.ledger.get_state({"did": [self.did]})                          # T_B^qry

    def auth_request(self) -> bool:
        return self.auth_server(self.auth_client())

    def auth_client(self):
        """Device: builds the request <REQ, r, s, c, t>; no cryptography ([31] Sec. V-B)."""
        return "REQ|" + os.urandom(8).hex() + "|" + str(int(time.time()))

    def auth_server(self, msg) -> bool:
        """Management servers ([31] Fig. 3, steps 3-12): MS_a signs the request, MS_b
        verifies it (querying the chain only for an unknown sender), MS_b signs the
        response, MS_a verifies it: 2 T_IBS^sign + 2 T_IBS^ver."""
        p = self.p
        sig_a = p.T_IBS_sign(self.ms_a_sk, msg)                                 # T_IBS^sign (MS_a)
        if self.did not in self.known:                                          # steps 5-6
            self._query()                                                       # T_B^qry
            self.known.add(self.did)
        ok = p.T_IBS_ver(self.ms_a_pk, msg, sig_a)                              # T_IBS^ver (MS_b)
        rsp = "RSP|" + msg
        sig_b = p.T_IBS_sign(self.ms_b_sk, rsp)                                 # T_IBS^sign (MS_b)
        ok = p.T_IBS_ver(self.ms_b_pk, rsp, sig_b) and ok                       # T_IBS^ver (MS_a)
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

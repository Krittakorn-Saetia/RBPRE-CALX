"""rbpre.protocol: Phases 1-5 of RBPRE-CALX (Section III-D), one method per step.

Roles: credential issuer (CI), KMS, patients, hospitals (each with an edge
TEE), doctors (requesters), the protected consent service (CS), the
authorization gateway (GW), the proxy, the graph server (Neo4j), encrypted
storage (MinIO), the authorization cache (Redis) and the consortium
blockchain (Fabric). They run in one process, but every external service is
real and every call to it is timed. The edge TEE is not emulated; its
processing runs as ordinary code (see DESIGN.md).

Every public method takes an optional Timer and records the cost of each
paper step in it, so the experiment drivers can report per-step breakdowns.

Notation follows the paper. H is SHA-256 over canonical encoding (encoding.H);
H(A) is the MiMC policy digest h_A, so that the same value is used in and out
of the circuit.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

from rbpre import aead, merkle, sig
from rbpre import rbabpre as rb
from rbpre.abpre import CPABPRE
from rbpre.encoding import H, kdf
from rbpre.zk import ZK, fe

# --------------------------------------------------------------- vocabulary
# Public consortium vocabulary for record-level filtering (Eq. 74).
CLASSES = ("vitals", "lab", "imaging", "rx", "ecg", "psych", "genetic", "admin")
SCOPE_CLASSES = {
    "cardiology": {"vitals", "lab", "rx", "ecg", "imaging"},
    "emergency": {"vitals", "lab", "rx", "ecg", "imaging", "admin"},
    "general": {"vitals", "lab", "rx"},
}
PURPOSE_CLASSES = {
    "treatment": set(CLASSES),
    "research": {"vitals", "lab", "imaging", "ecg"},
}

AUTH_LIFETIME_S = 60       # Delta_auth, challenge lifetime (Eq. 61)
SESSION_LIFETIME_S = 900   # upper bound on t_sess (Eq. 63)


class Rejected(Exception):
    """A protocol check failed (the paper's bottom)."""


class Timer:
    """Accumulates wall-clock time per named step (milliseconds)."""

    def __init__(self):
        self.ms: dict[str, float] = {}
        self.n: dict[str, int] = {}

    @contextmanager
    def step(self, name: str):
        t0 = time.perf_counter_ns()
        try:
            yield
        finally:
            self.add(name, (time.perf_counter_ns() - t0) / 1e6)

    def add(self, name: str, ms: float, n: int = 1) -> None:
        self.ms[name] = self.ms.get(name, 0.0) + ms
        self.n[name] = self.n.get(name, 0) + n

    def total(self) -> float:
        return sum(self.ms.values())


_NULL = Timer()


def now() -> int:
    return int(time.time())


# ----------------------------------------------------------------- entities


@dataclass
class Policy:
    """Consent policy A = (Role, Purpose, Scope, Time, Constraints) (Eq. 25),
    bounded to m required-attribute slots for the circuit."""

    req: list[str]
    purpose: str
    scope: str
    t_start: int
    t_end: int

    def slots(self, m: int) -> list[str]:
        if len(self.req) > m:
            raise ValueError(f"policy has {len(self.req)} required attributes, circuit has {m}")
        return [fe(a) for a in self.req] + [fe(0)] * (m - len(self.req))


@dataclass
class Hospital:
    did: str
    key: sig.SigningKey
    k_master: bytes
    attrs: list[str]  # S_A, certified source-domain attributes


@dataclass
class Doctor:
    did: str
    domain: str              # DID of the doctor's hospital (destination H_B)
    attrs: list[str]         # Attr_D
    cid: bytes
    t_vc: int
    zk_sk: str               # sk_D (Jubjub), kept by the doctor
    zk_pk: str               # pk_D, registered with the DID
    vc: str                  # VC_D (Eq. 18)
    abpre_sk: dict           # sk_{D,S_D} (Eq. 21)
    cb: bytes = field(default_factory=lambda: os.urandom(32))  # channel binding cb_D

    @property
    def pk_bytes(self) -> bytes:
        return bytes.fromhex(self.zk_pk)


@dataclass
class Patient:
    name: str
    key: sig.SigningKey
    pid: bytes               # PID = H(pk_P || r) (Eq. 23)
    home: str                # DID of the patient's home hospital
    e: int = 0               # current authorization epoch
    policy: Policy | None = None
    com_c: bytes = b""
    t_c: int = 0

    @property
    def handle(self) -> str:
        """Epoch handle on the chain; reveals neither PID nor the pseudonym mapping."""
        return H("rbpre-epoch", self.pid).hex()

    def pid_star(self, e: int | None = None) -> bytes:
        return H(self.pid, self.e if e is None else e)  # PID* = H(PID || e)


@dataclass
class Record:
    """One IoMT-EHR object to ingest."""

    hospital: str
    rtype: str
    rclass: str
    t_r: int
    readings: list[bytes]


@dataclass
class Challenge:
    """Gateway challenge state for one authorization (Eq. 50-51)."""

    purpose: str
    scope: str
    e: int
    pid_star: bytes
    n_g: bytes
    t_g: int
    pub: dict  # public statement x (Eq. 53), including h_ctx


@dataclass
class Session:
    doctor: Doctor
    patient: Patient
    sid: bytes
    auth_tok: bytes
    m_auth: bytes
    t_sess: int
    chi: rb.Descriptor
    h_ctx: str
    pid_star: bytes
    ctx: bytes


@dataclass
class Retrieved:
    rid: str
    hospital: str
    rclass: str
    plaintext: bytes


# ------------------------------------------------------------------- system


class RBPRESystem:
    """state_mode: "sync" reads the gateway's synchronized finalized state
    (the chain mirror kept from commit events); "query" asks the chaincode on
    every check."""

    def __init__(self, ledger, graph, store, cache, zk: ZK, m: int = 10, curve: str = "SS512",
                 state_mode: str = "sync"):
        self.ledger, self.graph, self.store, self.cache, self.zk = ledger, graph, store, cache, zk
        self.m = m
        if state_mode not in ("sync", "query"):
            raise ValueError("state_mode is 'sync' or 'query'")
        self.state_mode = state_mode
        self.scheme = CPABPRE(curve)
        self.hospitals: dict[str, Hospital] = {}
        # protected consent service state (off-chain, Eq. 24, 28, 49)
        self.cs_key = sig.keygen()
        self.cs_open_c: dict[bytes, dict] = {}       # ComC -> Open_C
        self.cs_open_r: dict[str, dict] = {}         # RID* -> Open_R
        self.cs_pids: dict[bytes, list[str]] = {}    # PID -> P_PID (historical pseudonyms)
        self.cs_policies: dict[bytes, Policy] = {}   # PID -> current policy
        # gateway state
        self.gw_key = sig.keygen()
        self.delegations: dict[tuple[str, str, bytes], dict] = {}  # (H_A, H_B, PID*) -> DelTok record
        self.linkage: dict[tuple, bytes] = {}        # (RID*, H_A, H_B, ComC, Purpose, e) -> FlagID
        self.trees: dict[str, merkle.MerkleTree] = {}  # PID* -> M_PID*
        self.pending_anchors: list[tuple[str, list]] = []  # asynchronous submissions

    def state(self, req: dict[str, list[str]]) -> dict:
        """Chain state for the checks of Eq. 62, 70, 79-82 and 86-88."""
        if self.state_mode == "sync":
            return self.ledger.mirror_state(req)
        return self.ledger.get_state(req)[0]

    # ================================================================ Phase 1

    def setup(self, universe=(), t: Timer = _NULL):
        """Step 1: (PP_RB, MSK_RB, sk_KMS, pk_KMS) <- Setup (Eq. 16) and the
        circuit-specific Groth16 setup (Eq. 17)."""
        base = [f"class:{c}" for c in CLASSES] + list(universe)
        with t.step("p1.rb_setup"):
            self.kms = rb.KMS(self.scheme, base)
        with t.step("p1.zk_setup"):
            self.zk_info = self.zk.setup("holder", self.m)
        with t.step("p1.issuer_keygen"):
            self.ci_sk, self.ci_pk = self.zk.keygen()

    def add_hospital(self, name: str, t: Timer = _NULL) -> Hospital:
        did = f"did:rb:{name}"
        attrs = [f"hosp:{name}"] + [f"class:{c}" for c in CLASSES]
        h = Hospital(did, sig.keygen(), os.urandom(32), attrs)
        with t.step("p1.kms_source_keygen"):
            self.kms.keygen_source(did, h.key.pk, attrs)  # Eq. 22
        with t.step("p1.chain_register_did"):
            self.ledger.register_dids([{"did": did, "pk": h.key.pk.hex(), "domain": did}])
        self.hospitals[did] = h
        return h

    def enroll_doctors(self, specs: list[tuple[str, str, list[str]]], t: Timer = _NULL,
                       t_vc: int | None = None) -> list[Doctor]:
        """Step 2: DID registration, VC_D (Eq. 18), CRec_D (Eq. 19), sk_{D,S_D} (Eq. 20-21).
        specs: (name, hospital DID, Attr_D)."""
        t_vc = t_vc or now() + 365 * 86400
        docs, dids, creds = [], [], []
        for name, domain, attrs in specs:
            if len(attrs) > self.m:
                raise ValueError("more credential attributes than circuit slots")
            with t.step("p1.doctor_keygen"):
                sk_d, pk_d = self.zk.keygen()
            did = f"did:rb:{name}"
            cid = os.urandom(32)
            slots = [fe(a) for a in attrs] + [fe(0)] * (self.m - len(attrs))
            with t.step("p1.vc_issue"):
                vc = self.zk.sign(self.ci_sk, self.zk.mimc(*slots, fe(did), fe(cid), fe(t_vc)))
            with t.step("p1.kms_keygen"):
                sk_ab = self.kms.keygen(did, bytes.fromhex(pk_d), list(attrs) + [rb.id_attr(did)])
            docs.append(Doctor(did, domain, list(attrs), cid, t_vc, sk_d, pk_d, vc, sk_ab))
            dids.append({"did": did, "pk": pk_d, "domain": domain})
            creds.append({"id": cid.hex(), "owner": did, "t": t_vc})
        with t.step("p1.chain_register_did"):
            self.ledger.register_dids(dids)
        with t.step("p1.chain_register_cred"):
            self.ledger.register_credentials(creds)
        return docs

    def enroll_patient(self, name: str, home: str, policy: Policy, t: Timer = _NULL,
                       t_c: int | None = None) -> Patient:
        """Step 3: PID, PID* (Eq. 23), P_PID (Eq. 24), Consent_P (Eq. 26),
        ComC (Eq. 27), Open_C (Eq. 28) and CRec_C on the CMC (Eq. 29)."""
        key = sig.keygen()
        r = os.urandom(32)
        p = Patient(name, key, H(key.pk, r), home)
        with t.step("p1.chain_epoch"):
            p.e, _ = self.ledger.advance_epoch(p.handle, H("rev", p.handle, 1).hex())
        self._set_consent(p, policy, t_c or now() + 365 * 86400, t, prev=b"")
        return p

    def _set_consent(self, p: Patient, policy: Policy, t_c: int, t: Timer, prev: bytes) -> None:
        pid_star = p.pid_star()
        with t.step("p1.consent_build"):
            h_a = self.policy_digest(policy)
            consent_p = p.key.sign(H(pid_star, bytes.fromhex(h_a), t_c, p.e))       # Eq. 26
            n_c = os.urandom(32)
            com_c = H(pid_star, bytes.fromhex(h_a), H(consent_p), t_c, p.e, n_c)    # Eq. 27
            self.cs_open_c[com_c] = dict(pid_star=pid_star, policy=policy, h_a=h_a, consent_p=consent_p,
                                         pk_p=p.key.pk, t_c=t_c, e=p.e, n_c=n_c)  # Eq. 28
            self.cs_pids.setdefault(p.pid, []).append(pid_star.hex())             # Eq. 24
            self.cs_policies[p.pid] = policy
        with t.step("p1.chain_consent"):
            self.ledger.register_consent(com_c.hex(), p.e, t_c, prev.hex())         # Eq. 29
        p.policy, p.com_c, p.t_c = policy, com_c, t_c

    def policy_digest(self, policy: Policy) -> str:
        """h_A = H(A), computed with MiMC so that the circuit can recompute it."""
        return self.zk.mimc(*policy.slots(self.m), fe("purpose:" + policy.purpose),
                            fe("scope:" + policy.scope), fe(policy.t_start), fe(policy.t_end))

    @staticmethod
    def ctx_of(h_a: str, h_b: str, scope: str, purpose: str, e: int) -> bytes:
        return H(h_a, h_b, scope, purpose, e)  # Eq. 32

    def issue_delegation(self, p: Patient, source: str, target: str, t: Timer = _NULL,
                         t_del: int | None = None) -> None:
        """Step 5: ctx (Eq. 32), DelTok_ctx (Eq. 33), DRec_ctx (Eq. 34)."""
        pol = p.policy
        t_del = t_del or now() + 180 * 86400
        pid_star = p.pid_star()
        with t.step("p1.deltok"):
            ctx = self.ctx_of(source, target, pol.scope, pol.purpose, p.e)
            n_del = os.urandom(16)
            msg = H(pid_star, ctx, p.com_c, p.e, t_del, n_del)
            tok = self.hospitals[source].key.sign(msg)
        with t.step("p1.chain_delegation"):
            self.ledger.register_delegation(H(tok).hex(), p.e, t_del)
        self.delegations[(source, target, pid_star)] = dict(
            ctx=ctx, tok=tok, msg=msg, h=H(tok).hex(), e=p.e, t_del=t_del)

    # ================================================================ Phase 2

    def ingest(self, p: Patient, records: list[Record], t: Timer = _NULL) -> list[str]:
        """Phase 2: device AEAD (Eq. 35), TEE verification and aggregation
        (Eq. 36-38), metadata commitment phi (Eq. 39), RID/RID* (Eq. 40),
        AD and CT_m (Eq. 41-42), CT_k (Eq. 43), storage (Eq. 44), graph
        reference (Eq. 45-46), d and ComR (Eq. 47-48), Open_R (Eq. 49).
        Returns the RID* values."""
        e, pid_star = p.e, p.pid_star()
        h_a = self.policy_digest(p.policy)
        packages, rows, coms, opens = [], [], [], []
        for rec in records:
            hosp = self.hospitals[rec.hospital]
            with t.step("p2.device_aead"):
                k_dev = kdf(hosp.k_master, f"dev:{rec.hospital}:{rec.rtype}", e)        # Eq. 30
                sealed = [(i, aead.encrypt(k_dev, m_i, H(f"dev:{rec.rtype}", rec.t_r, e)))
                          for i, m_i in enumerate(rec.readings)]                          # Eq. 35
            with t.step("p2.tee_aggregate"):
                vals = [aead.decrypt(k_dev, c, H(f"dev:{rec.rtype}", rec.t_r, e)) for _, c in sealed]
                m_agg = b"\n".join(dict.fromkeys(vals))                                  # Eq. 37
                meta = dict(pid=pid_star.hex(), type=rec.rtype, hosp=rec.hospital, t_r=rec.t_r,
                            cls=rec.rclass)                                              # Eq. 38
                r_m = os.urandom(32)
                phi = H(json.dumps(meta, sort_keys=True), r_m)                            # Eq. 39
            with t.step("p2.ehr_encrypt"):
                n_r = os.urandom(16)
                rid = H(pid_star, phi, e, n_r)
                rid_star = H(rid, e)                                                      # Eq. 40
                p_a = f"hosp:{rec.hospital.split(':')[-1]} AND class:{rec.rclass}"
                k_aes, ct_k = rb.enc(self.scheme, self.kms.pp, p_a)                       # Eq. 43
                ad = H(pid_star, rid_star, phi, bytes.fromhex(h_a), p.com_c, e)           # Eq. 41
                ct_m = aead.encrypt(k_aes, m_agg, ad)                                     # Eq. 42
                ct_k_b = self.scheme.dumps(ct_k)
                d = H(ct_m, ct_k_b)                                                       # Eq. 47
                com_r = H(rid_star, phi, p.com_c, e, d)                                   # Eq. 48
            packages.append((ct_m, ct_k_b))
            rows.append(dict(rid=rid_star.hex(), pid=pid_star.hex(), phi=phi.hex(), ha=h_a,
                             hosp=rec.hospital))
            coms.append({"id": rid_star.hex(), "v": com_r.hex()})
            opens.append((rid_star.hex(), dict(meta=meta, r_m=r_m, h_a=h_a, com_c=p.com_c, e=e,
                                               phi=phi)))
        with t.step("p2.store"):
            uris = self.store.put_many(packages)                                          # Eq. 44
        for row, uri in zip(rows, uris):
            row["uri"] = uri
        with t.step("p2.graph"):
            self.graph.add_records(rows)                                                  # Eq. 45-46
        with t.step("p2.chain_anchor"):
            self.ledger.anchor_records(coms)                                              # Eq. 48
        for rid_hex, op in opens:
            self.cs_open_r[rid_hex] = op                                                  # Eq. 49
        return [r["rid"] for r in rows]

    # ================================================================ Phase 3

    def authorize(self, doc: Doctor, p: Patient, purpose: str, scope: str, t: Timer = _NULL) -> Session:
        """Phase 3 end to end: challenge, holder proof, gateway verification."""
        ch = self.gw_challenge(doc, p, purpose, scope, t)
        proof = self.doc_prove(doc, p, ch, t)
        return self.gw_authorize(doc, p, ch, proof, t)

    def gw_challenge(self, doc: Doctor, p: Patient, purpose: str, scope: str, t: Timer = _NULL,
                     t_g: int | None = None) -> Challenge:
        """Step 1: Req (Eq. 50), pk_D from the DID registry, h_A, n_G, t_G and
        h_ctx (Eq. 51). t_g overrides the issuance time (freshness tests only)."""
        e, pid_star = p.e, p.pid_star()
        with t.step("p3.gw_challenge"):
            st = self.state({"did": [doc.did]})
            if st["did"].get(doc.did, {}).get("pk") != doc.zk_pk:
                raise Rejected("pk_D not bound to DID_D")
            pk_d = st["did"][doc.did]["pk"]
            h_a = self.policy_digest(self.cs_policies[p.pid])
            n_g, t_g = os.urandom(32), (now() if t_g is None else t_g)
            self.cache.issue_nonce(n_g, t_g, AUTH_LIFETIME_S)
            pub = dict(did=fe(doc.did), cid=fe(doc.cid), pid=fe(pid_star), purpose=fe("purpose:" + purpose),
                       scope=fe("scope:" + scope), epoch=e, tg=t_g, ng=fe(n_g), ha=h_a, cb=fe(doc.cb),
                       pk_ci=self.ci_pk, pk_d=pk_d)
            pub["hctx"] = self.zk.mimc(pub["did"], pub["cid"], pub["pid"], pub["purpose"], pub["scope"],
                                       fe(e), h_a, fe(t_g), pub["ng"], pub["cb"])           # Eq. 51
        return Challenge(purpose, scope, e, pid_star, n_g, t_g, pub)

    def doc_prove(self, doc: Doctor, p: Patient, ch: Challenge, t: Timer = _NULL) -> str:
        """Steps 1-2 on the doctor's device: sigma_D = Sign_skD(h_ctx) (Eq. 52)
        and pi <- ZK.Prove(pp_ZK, x, w) (Eq. 53-56)."""
        with t.step("p3.doc_sign"):
            sig_d = self.zk.sign(doc.zk_sk, ch.pub["hctx"])                                # Eq. 52
        policy = self.cs_policies[p.pid]
        slots = [fe(a) for a in doc.attrs] + [fe(0)] * (self.m - len(doc.attrs))
        wit = dict(attr=slots, tvc=doc.t_vc, vc=doc.vc, req=policy.slots(self.m),
                   purp=fe("purpose:" + policy.purpose), scope=fe("scope:" + policy.scope),
                   tstart=policy.t_start, tend=policy.t_end, sig_d=sig_d)
        with t.step("p3.doc_prove"):
            try:
                return self.zk.prove("holder", self.m, ch.pub, wit)["proof"]               # Eq. 56
            except Exception as ex:  # the doctor cannot produce a proof
                raise Rejected(f"no proof: {ex}") from ex

    def gw_authorize(self, doc: Doctor, p: Patient, ch: Challenge, proof: str,
                     t: Timer = _NULL) -> Session:
        """Steps 3-5: consent attestation (Eq. 57-60), Fresh and the checks of
        Eq. 62, atomic consumption of n_G, AuthTok (Eq. 63-65), session (Eq. 66)
        and descriptor chi (Eq. 67-68)."""
        purpose, scope, e, pid_star, n_g, t_g = ch.purpose, ch.scope, ch.e, ch.pid_star, ch.n_g, ch.t_g
        pub, h_ctx = ch.pub, ch.pub["hctx"]
        policy = self.cs_policies[p.pid]
        # ---- Step 3: consent service
        with t.step("p3.cs_consent"):
            sigma_c, open_c = self.cs_attest(p, purpose, scope)                            # Eq. 57-60
        # ---- Step 3: gateway verification (Eq. 61-62)
        with t.step("p3.gw_fresh"):
            t_now = now()
            issued = self.cache.peek_nonce(n_g)
            if issued is None or issued != t_g or not 0 <= t_now - t_g <= AUTH_LIFETIME_S:
                raise Rejected("stale, unknown or already used challenge")
        src = p.home
        dele = self.delegations.get((src, doc.domain, pid_star))
        if dele is None:
            raise Rejected("no delegation for this source-target pair")
        with t.step("p3.gw_state"):
            st = self.state({"cred": [doc.cid.hex()], "cons": [p.com_c.hex()],
                                              "del": [dele["h"]], "epoch": [p.handle]})
            self._check_state(st, doc, p, dele, t_now, e)
            if not sig.verify(self.cs_key.pk, sigma_c, H(p.com_c, purpose, scope, e, open_c["t_c"])):
                raise Rejected("consent attestation invalid")
            if not sig.verify(self.hospitals[src].key.pk, dele["tok"], dele["msg"]):
                raise Rejected("delegation token invalid")
        with t.step("p3.gw_zk_verify"):
            if not self.zk.verify("holder", self.m, pub, proof)["valid"]:
                raise Rejected("ZKP rejected")
        with t.step("p3.gw_consume"):
            if self.cache.consume_nonce(n_g) is None:
                raise Rejected("challenge already consumed (replay)")
        # ---- Step 4-5: AuthTok, session, descriptor
        with t.step("p3.gw_token"):
            sid = os.urandom(16)
            t_sess = min(t_now + SESSION_LIFETIME_S, doc.t_vc, open_c["t_c"], dele["t_del"],
                         policy.t_end)
            ctx = dele["ctx"]
            m_auth = H(doc.did, doc.cid, pid_star, p.com_c, ctx, e, sid, scope, purpose, t_sess,
                       bytes.fromhex(h_ctx), doc.cb)                                       # Eq. 63
            auth_tok = self.gw_key.sign(m_auth)                                            # Eq. 64
            com_auth = H(auth_tok, pid_star, e, sid)                                       # Eq. 65
            self.pending_anchors.append(("auth", [com_auth.hex()]))
            chi = rb.Descriptor(p.com_c, ctx, e, sid, scope, purpose)                       # Eq. 67-68
            sess = Session(doc, p, sid, auth_tok, m_auth, t_sess, chi, h_ctx, pid_star, ctx)
            blob = json.dumps(dict(did=doc.did, cid=doc.cid.hex(), cb=doc.cb.hex(), h_ctx=h_ctx,
                                   t_sess=t_sess)).encode()
            self.cache.put_session(sid, blob, t_sess - t_now, [p.handle, doc.did])        # Eq. 66
        return sess

    def cs_attest(self, p: Patient, purpose: str, scope: str):
        """Protected consent service: verify Open_C (Eq. 57-58), Permit (Eq. 59),
        sign sigma_C (Eq. 60)."""
        oc = self.cs_open_c[p.com_c]
        if not sig.verify(oc["pk_p"], oc["consent_p"], H(oc["pid_star"], bytes.fromhex(oc["h_a"]),
                                                         oc["t_c"], oc["e"])):
            raise Rejected("patient consent signature invalid")
        if H(oc["pid_star"], bytes.fromhex(oc["h_a"]), H(oc["consent_p"]), oc["t_c"], oc["e"],
             oc["n_c"]) != p.com_c:
            raise Rejected("consent commitment mismatch")
        pol, t_now = oc["policy"], now()
        if not (pol.purpose == purpose and pol.scope == scope and pol.t_start <= t_now <= pol.t_end):
            raise Rejected("Permit(A, Purpose, Scope, t_now) = 0")
        return self.cs_key.sign(H(p.com_c, purpose, scope, oc["e"], oc["t_c"])), oc

    def _check_state(self, st: dict, doc: Doctor, p: Patient, dele: dict, t_now: int, e: int) -> None:
        """ValidCred, CMC.VerifyConsent, ValidDel and e = e_cur against chain state."""
        cred = st["cred"].get(doc.cid.hex())
        if not cred or cred["status"] != "active" or cred["owner"] != doc.did or t_now > cred["t"]:
            raise Rejected("ValidCred = 0")
        cons = st["cons"].get(p.com_c.hex())
        if not cons or cons["status"] != "active" or cons["e"] != e or t_now > cons["t"]:
            raise Rejected("CMC.VerifyConsent = 0")
        d = st["del"].get(dele["h"])
        if not d or d["status"] != "active" or d["e"] != e or t_now > d["t"]:
            raise Rejected("ValidDel = 0")
        ep = st["epoch"].get(p.handle)
        if not ep or ep["e"] != e:
            raise Rejected("e != e_cur")

    def valid_state(self, s: Session, t: Timer = _NULL, label: str = "valid_state") -> None:
        """ValidState(chi, t_now) (Eq. 70, 82, 86): holder session, current chain
        state, AuthTok binding, epoch and session lifetime."""
        t_now = now()
        with t.step(label + ".session"):
            blob = self.cache.get_session(s.sid)
            if blob is None:
                raise Rejected("no live session (expired or invalidated)")
            meta = json.loads(blob)
            if meta["did"] != s.doctor.did or meta["cb"] != s.doctor.cb.hex() or t_now > s.t_sess:
                raise Rejected("holder-session binding failed")
        dele = self.delegations[(s.patient.home, s.doctor.domain, s.pid_star)]
        with t.step(label + ".chain"):
            st = self.state({"cred": [s.doctor.cid.hex()], "cons": [s.chi.com_c.hex()],
                                              "del": [dele["h"]], "epoch": [s.patient.handle]})
        with t.step(label + ".check"):
            self._check_state(st, s.doctor, s.patient, dele, t_now, s.chi.e)
            if not sig.verify(self.gw_key.pk, s.auth_tok, s.m_auth):
                raise Rejected("ValidAuth = 0")

    # ================================================================ Phase 4

    def discover(self, s: Session, t: Timer = _NULL, early_filter: bool = True) -> list[dict]:
        """Phase 4: admission (Eq. 70), candidate discovery (Eq. 71), metadata
        opening and record-level filtering (Eq. 72-75), linkage (Eq. 76-78),
        record and linkage verification (Eq. 79-81). Returns T_auth entries.

        early_filter=False is the ablation variant that verifies the whole
        candidate set before applying record-level authorization."""
        p, doc = s.patient, s.doctor
        self.valid_state(s, t, "p4.admission")                                         # Eq. 70
        with t.step("p4.graph"):
            p_pid = list(self.cs_pids[p.pid])                                          # P_PID
            t_d = self.graph.candidates(p_pid)                                         # Eq. 71
        pol = self.cs_policies[p.pid]
        with t.step("p4.filter"):
            checked = []
            for c in t_d:
                op = self.cs_open_r.get(c["rid"])                                      # Eq. 72
                if op is None or H(json.dumps(op["meta"], sort_keys=True), op["r_m"]).hex() != c["phi"]:
                    continue                                                           # Eq. 73
                if op["meta"]["pid"] not in p_pid or op["meta"]["hosp"] != c["hosp"]:
                    continue
                c["open"] = op
                c["auth"] = self.authorized(doc, op["meta"], s, pol)                    # Eq. 74
                checked.append(c)
            t_f = [c for c in checked if c["auth"]] if early_filter else checked       # Eq. 75
        self.last_candidates = checked  # for the ablation variants that skip selection
        # ---- Step 4: linkage identifiers (Eq. 76-77)
        with t.step("p4.linkage_prepare"):
            new_flags = []
            for c in t_f:
                key = (c["rid"], c["hosp"], doc.domain, s.chi.com_c, s.chi.purpose, s.chi.e)
                if key not in self.linkage:
                    flag = H(s.pid_star, c["rid"], c["hosp"], doc.domain, s.chi.com_c, s.chi.purpose,
                             s.chi.e, os.urandom(16))
                    self.linkage[key] = flag
                    new_flags.append(flag)
                c["flag"] = self.linkage[key]
        # ---- Step 5: record commitments (Eq. 79)
        with t.step("p4.fetch"):
            blobs = self.store.get_many([c["uri"] for c in t_f])
        with t.step("p4.chain_records"):
            st = self.state({"rec": [c["rid"] for c in t_f]})
        with t.step("p4.verify_records"):
            ok = []
            for c, (ct_m, ct_k) in zip(t_f, blobs):
                op = c["open"]
                d = H(ct_m, ct_k)
                if st["rec"].get(c["rid"]) != H(bytes.fromhex(c["rid"]), op["phi"], op["com_c"],
                                                op["e"], d).hex():
                    continue
                c["ct"] = (ct_m, ct_k)
                ok.append(c)
            if not early_filter:
                ok = [c for c in ok if c["auth"]]
        # ---- finalize new linkage, anchor Root_PID* (Eq. 76-78)
        pid_hex = s.pid_star.hex()
        ok_flags = {c["flag"] for c in ok}
        new_flags = [f for f in new_flags if f in ok_flags]
        if new_flags:
            tree = self.trees.setdefault(pid_hex, merkle.MerkleTree([]))
            with t.step("p4.merkle_update"):
                for f in new_flags:
                    tree.leaves.append(f)
                tree._build()
            with t.step("p4.chain_linkage"):
                self.ledger.anchor_flags([{"id": f.hex(), "e": s.chi.e} for f in new_flags])
                self.ledger.set_root(pid_hex, tree.root.hex())
        tree = self.trees.get(pid_hex)
        with t.step("p4.chain_linkage_state"):
            st = self.state({"flag": [c["flag"].hex() for c in ok], "root": [pid_hex]})
        with t.step("p4.verify_linkage"):
            root = bytes.fromhex(st["root"].get(pid_hex, "00"))
            index = {leaf: i for i, leaf in enumerate(tree.leaves)} if tree else {}
            t_auth = []
            for c in ok:
                f = st["flag"].get(c["flag"].hex())
                i = index.get(c["flag"])
                if f and f["status"] == "active" and i is not None and \
                        merkle.verify(c["flag"], tree.proof(i), root):                  # Eq. 80
                    t_auth.append(c)                                                    # Eq. 81
        self.valid_state(s, t, "p4.release")
        return t_auth

    @staticmethod
    def scope_match(meta: dict, s: Session, pol: Policy) -> bool:
        return meta["cls"] in SCOPE_CLASSES.get(s.chi.scope, ()) and pol.t_start <= meta["t_r"] <= pol.t_end

    @staticmethod
    def purpose_permit(pol: Policy, meta: dict, s: Session) -> bool:
        return s.chi.purpose == pol.purpose and meta["cls"] in PURPOSE_CLASSES.get(s.chi.purpose, ())

    def policy_match(self, doc: Doctor, meta: dict, s: Session) -> bool:
        """Applicable delegation for the record's source domain (Eq. 74)."""
        d = self.delegations.get((meta["hosp"], doc.domain, s.pid_star))
        return d is not None and d["e"] == s.chi.e

    def authorized(self, doc: Doctor, meta: dict, s: Session, pol: Policy) -> bool:
        return self.scope_match(meta, s, pol) and self.purpose_permit(pol, meta, s) and \
            self.policy_match(doc, meta, s)                                            # Eq. 74

    # ================================================================ Phase 5

    def transform(self, s: Session, t_auth: list[dict], t: Timer = _NULL, use_cache: bool = True,
                  selective: bool = True, all_candidates: list[dict] | None = None) -> list[dict]:
        """Phase 5 Steps 1-2 and 4: KMS validation and re-key states (Eq. 82-84,
        94-95), retrieval-set signature (Eq. 85), proxy checks (Eq. 86-88) and
        ReEnc (Eq. 89). selective=False is the ablation variant that transforms
        every candidate key capsule (all_candidates)."""
        doc, p = s.doctor, s.patient
        targets = t_auth if selective else (all_candidates or t_auth)
        missing = [c for c in targets if "ct" not in c]
        if missing:  # candidates that discovery did not fetch (non-selective variant)
            with t.step("p5.fetch_candidates"):
                for c, blob in zip(missing, self.store.get_many([c["uri"] for c in missing])):
                    c["ct"] = blob
        self.valid_state(s, t, "p5.kms_state")                                         # Eq. 82
        h_chi = s.chi.digest()
        p_b = f"{rb.id_attr(doc.did)} AND {doc.attrs[0]}"
        with t.step("p5.gw_sign_set"):
            h_set = H(*sorted(c["rid"] for c in targets))
            sigma_t = self.gw_key.sign(H(h_chi, doc.pk_bytes, h_set))                  # Eq. 85
        # ---- re-key states per (source domain, policy) (Eq. 83-84, 94-95)
        states = {}
        for c in targets:
            ct_k = self.scheme.loads(c["ct"][1])
            c["ct_k"] = ct_k
            key = (c["hosp"], ct_k["policy"])
            if key in states:
                continue
            kappa = H(h_chi, doc.pk_bytes, c["hosp"], H(ct_k["policy"]), H(p_b))        # Eq. 94
            rk = None
            if use_cache:
                with t.step("p5.rk_cache_get"):
                    blob = self.cache.get_rekey(kappa)
                    rk = self.scheme.loads(blob) if blob else None
            if rk is None:
                with t.step("p5.kms_rekeygen"):
                    rk = self.kms.rekeygen(c["hosp"], ct_k["policy"], p_b, doc.pk_bytes, s.chi)
                if use_cache:
                    with t.step("p5.rk_cache_put"):
                        self.cache.put_rekey(kappa, self.scheme.dumps(rk), s.t_sess - now(),
                                             [p.handle, doc.did])
                t.add("p5.rk_miss", 0.0)
            else:
                t.add("p5.rk_hit", 0.0)
            states[key] = rk
        # ---- proxy (Eq. 86-89)
        self.valid_state(s, t, "p5.proxy_state")                                      # Eq. 86
        with t.step("p5.proxy_check_set"):
            if not sig.verify(self.gw_key.pk, sigma_t, H(h_chi, doc.pk_bytes, h_set)):
                raise Rejected("retrieval-set signature invalid")
        with t.step("p5.proxy_fetch"):
            blobs = self.store.get_many([c["uri"] for c in targets])
        with t.step("p5.proxy_chain"):
            st = self.state({"rec": [c["rid"] for c in targets]})
        out = []
        for c, (ct_m, ct_k_b) in zip(targets, blobs):
            op = c["open"]
            with t.step("p5.proxy_binding"):
                if st["rec"].get(c["rid"]) != H(bytes.fromhex(c["rid"]), op["phi"], op["com_c"], op["e"],
                                                H(ct_m, ct_k_b)).hex():                # Eq. 87-88
                    raise Rejected("ciphertext-record binding failed")
            with t.step("p5.proxy_reenc"):
                ct_kb = rb.reencrypt(self.scheme, self.kms.pp, self.kms.pk_kms, c["ct_k"],
                                     states[(c["hosp"], c["ct_k"]["policy"])], s.chi)  # Eq. 89
            out.append(dict(c, ct_kb=ct_kb, ct_m=ct_m))
        # ---- sharing commitments, asynchronous (Eq. 90)
        with t.step("p5.share_commit"):
            shares = [H(s.pid_star, c["rid"], c["hosp"], doc.domain, h_chi, s.chi.e).hex() for c in out]
            self.pending_anchors.append(("share", shares))
        return out

    def recipient_decrypt(self, s: Session, items: list[dict], t: Timer = _NULL) -> list[Retrieved]:
        """Phase 5 Step 3: K_AES <- Dec (Eq. 91), AD_i (Eq. 92), AEAD.Dec (Eq. 93)."""
        res = []
        for c in items:
            op = c["open"]
            with t.step("p5.doc_decrypt"):
                k = rb.dec(self.scheme, self.kms.pp, s.doctor.abpre_sk, c["ct_kb"])
                ad = H(bytes.fromhex(op["meta"]["pid"]), bytes.fromhex(c["rid"]), op["phi"],
                       bytes.fromhex(op["h_a"]), op["com_c"], op["e"])
                pt = aead.decrypt(k, c["ct_m"], ad)
            res.append(Retrieved(c["rid"], c["hosp"], op["meta"]["cls"], pt))
        return res

    def retrieve(self, s: Session, t: Timer = _NULL) -> list[Retrieved]:
        """End-to-end longitudinal retrieval for an authorized session (Phases 4-5)."""
        t_auth = self.discover(s, t)
        return self.recipient_decrypt(s, self.transform(s, t_auth, t), t)

    def flush_anchors(self, t: Timer = _NULL) -> int:
        """Submit the queued ComAuth / ComShare commitments (asynchronous path)."""
        n = 0
        with t.step("async.chain_anchor"):
            while self.pending_anchors:
                kind, coms = self.pending_anchors.pop(0)
                if kind == "auth":
                    for c in coms:
                        self.ledger.anchor_auth(c)
                else:
                    self.ledger.anchor_shares(coms)
                n += len(coms)
        return n

    # ======================================================== Phase 5 Step 5

    def _advance(self, p: Patient, rev: dict, t: Timer) -> int:
        """Advance the patient's epoch and finalize ComRev_{e+1} (Eq. 96-97),
        then invalidate affected sessions and re-key states."""
        with t.step("rev.chain_epoch"):
            com_rev = H(json.dumps(rev, sort_keys=True)).hex()
            p.e, _ = self.ledger.advance_epoch(p.handle, com_rev)
        with t.step("rev.cache_invalidate"):
            removed = self.cache.invalidate(p.handle)
        t.add("rev.entries_invalidated", 0.0, removed)
        return removed

    def withdraw_consent(self, p: Patient, t: Timer = _NULL) -> None:
        """Consent withdrawal revokes CRec_C (Phase 5 Step 5)."""
        with t.step("rev.chain_consent"):
            self.ledger.set_status("cons", p.com_c.hex(), "revoked")
        self._advance(p, {"e": p.e + 1, "rev_consent": p.com_c.hex()}, t)

    def update_policy(self, p: Patient, policy: Policy, t: Timer = _NULL) -> None:
        """Policy update: new epoch, new pseudonym PID*_{e+1} and ComC^{e+1}
        (Eq. 98), superseding the previous consent state."""
        old = p.com_c
        self._advance(p, {"e": p.e + 1, "superseded": old.hex()}, t)
        self._set_consent(p, policy, p.t_c, t, prev=old)

    def revoke_credential(self, doc: Doctor, t: Timer = _NULL) -> int:
        """Credential revocation: CRec_D -> revoked, and the doctor's sessions
        and re-key states are invalidated."""
        with t.step("rev.chain_cred"):
            self.ledger.set_status("cred", doc.cid.hex(), "revoked")
        with t.step("rev.cache_invalidate"):
            removed = self.cache.invalidate(doc.did)
        t.add("rev.entries_invalidated", 0.0, removed)
        return removed

    def revoke_delegation(self, p: Patient, source: str, target: str, t: Timer = _NULL) -> None:
        d = self.delegations[(source, target, p.pid_star())]
        with t.step("rev.chain_del"):
            self.ledger.set_status("del", d["h"], "revoked")
        self._advance(p, {"e": p.e + 1, "rev_del": d["h"]}, t)

"""Synthetic longitudinal workload shared by Experiments 2-7.

A World holds one RBPRE-CALX system with H hospitals, one requester (doctor)
at the first hospital, and target patients whose histories are spread over
all hospitals. Every hospital, including the requester's own, has an active
delegation to the requester's domain, so domain eligibility never filters a
record. The authorized fraction |T_auth|/N is set by record class: a record
is in scope with probability `ratio` (class drawn from the classes the
cardiology scope and treatment purpose permit), otherwise its class is one
the policy excludes (psych, genetic, admin).

Background records of other patients go into the retrieval graph and the
repository index only (RBPRE-CALX never fetches them; scanning baselines
must still pass over them).
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass, field

from baselines.common import IndexEntry
from rbpre.encoding import H
from rbpre.protocol import PURPOSE_CLASSES, SCOPE_CLASSES, Policy, RBPRESystem, Record, now
from rbpre.zk import ZK

IN_SCOPE = sorted(SCOPE_CLASSES["cardiology"] & PURPOSE_CLASSES["treatment"])
OUT_SCOPE = ["psych", "genetic", "admin"]
PAYLOAD_BYTES = 256


@dataclass
class Target:
    patient: object
    owner: bytes                       # owner tag for scanning baselines
    n: int = 0
    rids: list[str] = field(default_factory=list)
    authorized: set[str] = field(default_factory=set)  # ground truth T_auth


class World:
    def __init__(self, ledger, graph, store, cache, hospitals: int = 3, m: int = 10, seed: int = 1):
        self.zk = ZK()
        self.s = RBPRESystem(ledger, graph, store, cache, self.zk, m=m)
        self.s.setup()
        self.rnd = random.Random(seed)
        tag = os.urandom(3).hex()
        self.tag = tag
        self.hosp = [self.s.add_hospital(f"H{i:02d}{tag}").did for i in range(hospitals)]
        attrs = ["role:physician", "dept:cardiology"]
        self.doc, = self.s.enroll_doctors([(f"doc{tag}", self.hosp[0], attrs)])
        t0 = now()
        self.t0 = t0
        self.policy = Policy(attrs, "treatment", "cardiology", t0 - 3 * 365 * 86400, t0 + 365 * 86400)
        self.index: list[IndexEntry] = []
        self.targets: list[Target] = []
        self.background_pids: list[str] = []

    def new_target(self) -> Target:
        p = self.s.enroll_patient(f"pat{len(self.targets)}{self.tag}", self.hosp[-1], self.policy)
        for h in self.hosp:
            self.s.issue_delegation(p, h, self.doc.domain)
        t = Target(p, H("owner", p.pid))
        self.targets.append(t)
        return t

    def grow(self, t: Target, n_total: int, ratio: float, batch: int = 1000) -> None:
        """Ingest records until the target has n_total of them."""
        while t.n < n_total:
            k = min(batch, n_total - t.n)
            recs, auth = [], []
            for _ in range(k):
                ok = self.rnd.random() < ratio
                cls = self.rnd.choice(IN_SCOPE if ok else OUT_SCOPE)
                recs.append(Record(self.rnd.choice(self.hosp), "obs", cls,
                                   self.t0 - self.rnd.randrange(2 * 365 * 86400),
                                   [os.urandom(PAYLOAD_BYTES)]))
                auth.append(ok)
            rids = self.s.ingest(t.patient, recs)
            for rid, rec, ok in zip(rids, recs, auth):
                self.index.append(IndexEntry(t.owner, rid, rec.hospital, rec.rclass))
                if ok:
                    t.authorized.add(rid)
            t.rids += rids
            t.n += k

    def add_background(self, n: int, patients: int = 10, batch: int = 5000) -> None:
        """Other patients' records: graph references and index entries only."""
        owners = [H("owner", os.urandom(16)) for _ in range(patients)]
        pids = [H("bgpid", o).hex() for o in owners]
        self.background_pids += pids
        rows = []
        for i in range(n):
            j = i % patients
            rid = H("bg", os.urandom(16)).hex()
            hosp = self.rnd.choice(self.hosp)
            rows.append(dict(rid=rid, pid=pids[j], phi=os.urandom(32).hex(), ha="00", uri="", hosp=hosp))
            self.index.append(IndexEntry(owners[j], rid, hosp, self.rnd.choice(IN_SCOPE + OUT_SCOPE)))
        for i in range(0, len(rows), batch):
            self.s.graph.add_records(rows[i:i + batch])

    def close(self, clean: bool = True) -> None:
        if clean:
            pids = [x for t in self.targets for x in self.s.cs_pids.get(t.patient.pid, [])]
            self.s.graph.delete_patients(pids + self.background_pids)
        self.zk.close()

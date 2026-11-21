#!/usr/bin/env python3
"""One end-to-end run of Phases 1-5 with a per-step latency breakdown.

    python smoke_protocol.py            # Fabric test-network (channel rbpre)
    python smoke_protocol.py --offline  # in-memory ledger, no Fabric

Needs Neo4j, MinIO and Redis (infra/services.sh up) and zk/rbzk.
"""

from __future__ import annotations

import argparse
import os
import random

from rbpre.cache import AuthCache
from rbpre.chain import FabricLedger, MemoryLedger
from rbpre.graph import RetrievalGraph
from rbpre.protocol import CLASSES, Policy, RBPRESystem, Record, Timer, now
from rbpre.storage import EHRStore
from rbpre.zk import ZK


def show(title: str, t: Timer) -> None:
    print(f"\n{title}: {t.total():.1f} ms")
    for k, v in sorted(t.ms.items(), key=lambda kv: -kv[1]):
        n = t.n[k]
        print(f"  {k:<28} {v:10.1f} ms" + (f"   ({n}x)" if n > 1 else ""))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--records", type=int, default=200)
    ap.add_argument("--hospitals", type=int, default=3)
    ap.add_argument("--m", type=int, default=10)
    args = ap.parse_args()

    graph, zk = RetrievalGraph(), ZK()
    graph.setup()
    store = EHRStore()
    store.setup()
    s = RBPRESystem(MemoryLedger() if args.offline else FabricLedger(), graph, store, AuthCache(), zk,
                    m=args.m)
    t = Timer()
    s.setup(t=t)
    tag = os.urandom(3).hex()
    hosp = [s.add_hospital(f"H{i}{tag}", t).did for i in range(args.hospitals)]
    doc, = s.enroll_doctors([(f"doc{tag}", hosp[0], ["role:physician", "dept:cardiology"])], t)
    t0 = now()
    pol = Policy(["role:physician", "dept:cardiology"], "treatment", "cardiology",
                 t0 - 365 * 86400, t0 + 365 * 86400)
    p = s.enroll_patient(f"pat{tag}", hosp[1 % len(hosp)], pol, t)
    for h in hosp:
        s.issue_delegation(p, h, hosp[0], t)
    show("Phase 1 (setup and enrollment)", t)

    rnd = random.Random(1)
    recs = [Record(rnd.choice(hosp), "obs", rnd.choice(CLASSES), t0 - rnd.randrange(86400 * 300),
                   [os.urandom(64)]) for _ in range(args.records)]
    t = Timer()
    s.ingest(p, recs, t)
    show(f"Phase 2 (ingest {args.records} records)", t)

    t = Timer()
    sess = s.authorize(doc, p, "treatment", "cardiology", t)
    show("Phase 3 (authorization, fresh proof)", t)

    for label in ("Phases 4-5 (first retrieval)", "Phases 4-5 (same session, reuse)"):
        t = Timer()
        got = s.retrieve(sess, t)
        show(f"{label}: {len(got)} of {args.records} records", t)

    t = Timer()
    n = s.flush_anchors(t)
    show(f"Asynchronous anchoring ({n} commitments)", t)
    graph.delete_patients(s.cs_pids[p.pid])
    graph.close()
    zk.close()


if __name__ == "__main__":
    main()

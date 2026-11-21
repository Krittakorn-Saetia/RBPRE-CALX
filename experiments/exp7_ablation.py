#!/usr/bin/env python3
"""Experiment 7: component ablation, swept over |T_auth|/N.

For each ratio (default 1, 5, 10, 25, 50, 75, 100 %) one patient with N
records is built, and the end-to-end retrieval (discovery + transformation)
of five variants is measured:

  full                 the full framework, as a repeated request in a valid
                       session (holder-bound session and re-key states reused)
  (i)   no reuse       new authorization with a fresh proof per request, and
                       no re-key cache
  (ii)  no early filter discovery verifies the whole candidate set before
                       record-level authorization
  (iii) no selective PRE every candidate key capsule is transformed
  (iv)  (ii) + (iii)

Variants (iii) and (iv) are performance-only controls: they transform records
that are not authorized. The per-stage times are kept for stacked bars.

    python -m experiments.exp7_ablation [--n 10000] [--ratios ...] [--runs 30]
"""

from __future__ import annotations

import argparse

from experiments.harness import quiet, save_machine, services, write_rows
from experiments.workload import World
from rbpre.protocol import Timer

STAGES = {
    "authorization": ("p3.",),
    "state checks": ("p4.admission", "p4.release", "p5.kms_state", "p5.proxy_state"),
    "discovery": ("p4.graph", "p4.filter"),
    "verification": ("p4.fetch", "p4.chain_records", "p4.verify_records", "p4.linkage", "p4.chain_linkage",
                     "p4.verify_linkage", "p4.merkle_update"),
    "transformation": ("p5.",),
}


def stage_of(step: str) -> str:
    for name in ("authorization", "state checks", "discovery", "verification", "transformation"):
        if any(step.startswith(p) for p in STAGES[name]):
            return name
    return "other"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10000)
    ap.add_argument("--ratios", type=float, nargs="+", default=[0.01, 0.05, 0.10, 0.25, 0.50, 0.75, 1.0])
    ap.add_argument("--hospitals", type=int, default=5)
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--m", type=int, default=10)
    args = ap.parse_args()
    save_machine()
    ledger, graph, store, cache = services(True, bucket="ehr-exp7")
    w = World(ledger, graph, store, cache, hospitals=args.hospitals, m=args.m)
    s, doc = w.s, w.doc
    rows, stages = [], []
    for ratio in args.ratios:
        target = w.new_target()
        w.grow(target, args.n, ratio)
        p = target.patient
        sess = s.authorize(doc, p, "treatment", "cardiology")
        ref = s.discover(sess)                      # warm-up: linkage entries
        s.transform(sess, ref)
        s.discover(sess, early_filter=False)        # warm-up for the unfiltered linkage set
        s.pending_anchors.clear()
        # one record per (hospital, class): enough to create every re-key state of a session
        prime = list({(c["hosp"], c["open"]["meta"]["cls"]): c for c in ref}.values())

        def fresh_session():
            """A new valid session with its re-key states cached (sessions live
            at most SESSION_LIFETIME_S, so each run starts its own)."""
            se = s.authorize(doc, p, "treatment", "cardiology")
            s.transform(se, [dict(c) for c in prime])
            s.pending_anchors.clear()
            return se

        def full(t):
            s.transform(sess, s.discover(sess, t), t)

        def no_reuse(t):
            se = s.authorize(doc, p, "treatment", "cardiology", t)
            s.transform(se, s.discover(se, t), t, use_cache=False)

        def no_filter(t):
            s.transform(sess, s.discover(sess, t, early_filter=False), t)

        def no_selective(t):
            ta = s.discover(sess, t)
            s.transform(sess, ta, t, selective=False, all_candidates=s.last_candidates)

        def neither(t):
            ta = s.discover(sess, t, early_filter=False)
            s.transform(sess, ta, t, selective=False, all_candidates=s.last_candidates)

        variants = [("full", full), ("(i) no reuse", no_reuse), ("(ii) no early filter", no_filter),
                    ("(iii) no selective PRE", no_selective), ("(iv) no filter + no selective", neither)]
        for name, fn in variants:  # warm-up, not recorded
            sess = fresh_session()
            fn(Timer())
        for r in range(args.runs):
            for name, fn in variants:
                sess = fresh_session()
                t = Timer()
                with quiet():
                    fn(t)
                s.pending_anchors.clear()
                rows.append(dict(variant=name, ratio=ratio, n=args.n, t_auth=len(target.authorized), run=r,
                                 ms=t.total()))
                agg: dict[str, float] = {}
                for k, v in t.ms.items():
                    agg[stage_of(k)] = agg.get(stage_of(k), 0.0) + v
                stages += [dict(variant=name, ratio=ratio, run=r, stage=k, ms=v) for k, v in agg.items()]
        cur = [x for x in rows if x["ratio"] == ratio]
        print(f"ratio={ratio:<5} |T_auth|={len(target.authorized):<6} " + "  ".join(
            f"{v}: {sum(x['ms'] for x in cur if x['variant'] == v) / args.runs:8.0f}" for v, _ in variants))
        write_rows("e7_runs.csv", rows)
        write_rows("e7_stages.csv", stages)
    w.close()
    store.clear()


if __name__ == "__main__":
    main()

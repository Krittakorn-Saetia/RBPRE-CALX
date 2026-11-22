#!/usr/bin/env python3
"""Experiment 6: end-to-end longitudinal retrieval vs the number of hospitals.

N records of one patient are spread over H hospitals (H in 1, 2, 5, 10, 15,
20), with |T_auth|/N = --ratio.

  RBPRE-CALX  one holder-bound session, then discovery (admission, graph,
              filtering, linkage, record and linkage verification) and
              selective transformation with a re-key cache miss; the
              authorization proof itself is reported separately (Exp 1)
  [25], [27], [31]  per-domain authentication (one auth_request per hospital),
              repository scan with per-record validation, transformation and,
              where supported, verification, of all of the patient's records
              or of T_auth (filter-equalized)
  PRE         scan, per-record re-key and re-encryption, binding check

Every scheme reads the ciphertexts it processes from the same MinIO store
with the same call (store.get_many) that RBPRE-CALX's proxy and verifier use.

    python -m experiments.exp6_hospitals [--hospitals 1 2 5 10 15 20] [--n 5000] [--runs 30]
"""

from __future__ import annotations

import argparse
import time

from baselines.common import Prims
from baselines.repository import DBRepository
from baselines.schemes import Luo31, PlainPRE, Wang25, Yan27
from experiments.exp234_retrieval import Series
from experiments.harness import save_machine, services, write_rows
from experiments.workload import World
from rbpre import rbabpre as rb
from rbpre.protocol import Timer


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hospitals", type=int, nargs="+", default=[1, 2, 5, 10, 15, 20])
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--ratio", type=float, default=0.10)
    ap.add_argument("--background", type=float, default=1.0)
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--runs-heavy", type=int, default=5)
    ap.add_argument("--heavy-s", type=float, default=60.0)
    ap.add_argument("--m", type=int, default=10)
    args = ap.parse_args()
    save_machine()
    ser = Series(args.runs, args.runs_heavy, args.heavy_s)
    rows, steps = [], []
    for h in args.hospitals:
        ledger, graph, store, cache = services(True, bucket="ehr-exp6")
        w = World(ledger, graph, store, cache, hospitals=h, m=args.m, seed=h)
        s, doc = w.s, w.doc
        target = w.new_target()
        w.grow(target, args.n, args.ratio)
        w.add_background(int(args.background * args.n))
        # warm-up: creates the linkage entries
        sess = s.authorize(doc, target.patient, "treatment", "cardiology")
        s.transform(sess, s.discover(sess))
        s.pending_anchors.clear()
        auth_set = set(target.authorized)
        run = [0]

        def timed_rbpre():
            t = Timer()
            se = s.authorize(doc, target.patient, "treatment", "cardiology")
            t0 = time.perf_counter_ns()
            s.transform(se, s.discover(se, t), t)
            steps.extend(dict(hospitals=h, run=run[0], step=k, ms=v) for k, v in t.ms.items())
            run[0] += 1
            s.pending_anchors.clear()
            return (time.perf_counter_ns() - t0) / 1e6

        xs = [timed_rbpre() for _ in range(args.runs)]
        rows += [dict(scheme="RBPRE-CALX", variant="filtered", hospitals=h, n=args.n, run=i, ms=v,
                      runs=len(xs)) for i, v in enumerate(xs)]

        pr = Prims()
        base = [Wang25(pr, ledger), Yan27(pr, ledger, m=args.m), Luo31(pr, ledger)]
        base[2].bind(doc.did)
        # every scheme reads the ciphertexts it processes from the same MinIO store, with the same call
        # RBPRE-CALX's proxy and verifier use (store.get_many)
        uris = {r["rid"]: r["uri"] for r in s.graph.candidates(list(s.cs_pids[target.patient.pid]))}
        repo = DBRepository()           # the hospitals' repositories: one indexed query per hospital
        repo.sync(w.index)
        for b in base:
            for variant, subset in (("all", None), ("filtered", auth_set)):
                def e2e(b=b, subset=subset):
                    for _ in range(h):
                        b.auth_request()                       # cross-domain authentication per hospital
                    recs = b.retrieve(repo, target.owner, subset)
                    store.get_many([uris[e.rid] for e in recs])
                    b.transform(recs)
                    if hasattr(b, "verify"):
                        b.verify(recs)
                ys = ser(e2e)
                rows += [dict(scheme=b.name, variant=variant, hospitals=h, n=args.n, run=i, ms=v, runs=len(ys))
                         for i, v in enumerate(ys)]
        pre = PlainPRE(s.scheme, s.kms, pr, ledger)
        p_b = f"{rb.id_attr(doc.did)} AND {doc.attrs[0]}"
        for variant, subset in (("all", None), ("filtered", auth_set)):
            def pre_e2e(subset=subset):
                found = [e.rid for e in pre.retrieve(repo, target.owner, subset)]
                sel = [dict(rid=r, hosp=s.cs_open_r[r]["meta"]["hosp"], ct=blob, open=s.cs_open_r[r],
                            ct_k=s.scheme.loads(blob[1]))
                       for r, blob in zip(found, store.get_many([uris[r] for r in found]))]
                pre.transform(sel, doc.pk_bytes, p_b, sess.chi)
                pre.verify(sel)
            ys = ser(pre_e2e)
            rows += [dict(scheme="PRE", variant=variant, hospitals=h, n=args.n, run=i, ms=v, runs=len(ys))
                     for i, v in enumerate(ys)]
        cur = [x for x in rows if x["hospitals"] == h]
        print(f"H={h:<3} " + "  ".join(
            f"{k[0]}/{k[1]}: {sum(x['ms'] for x in cur if (x['scheme'], x['variant']) == k) / max(1, sum(1 for x in cur if (x['scheme'], x['variant']) == k)):8.0f}"
            for k in dict.fromkeys((x["scheme"], x["variant"]) for x in cur)))
        write_rows("e6_runs.csv", rows)
        write_rows("e6_steps.csv", steps)
        repo.clear()
        repo.close()
        w.close()
        store.clear()
        graph.close()


if __name__ == "__main__":
    main()

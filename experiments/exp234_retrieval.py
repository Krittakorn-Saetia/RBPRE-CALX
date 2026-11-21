#!/usr/bin/env python3
"""Experiments 2-4 on one growing patient history.

  Exp 2  longitudinal retrieval latency vs N linked records: RBPRE-CALX
         T_ret of Eq. 158 (admission, historical-pseudonym resolution, graph
         discovery, metadata-opening verification and record-level filtering);
         the whole of Phase 4 including verification is also kept, as variant
         "with verification". Baselines locate the patient's records by
         repository scan plus their own per-record validation.
  Exp 3  cross-domain transformation cost vs N: RBPRE-CALX Phase 5 on T_auth,
         with a re-key cache miss (new session) and hit (same session);
         baselines transform every patient record.
  Exp 4  verification overhead vs the number of verified records |T_f|.

Every baseline series is run twice: on all of the patient's records, and
filter-equalized (handed T_auth, or T_f for Exp 4).

A series whose first run at a point takes longer than --heavy-s seconds is
capped at --runs-heavy runs for that point; the CSV records how many runs
each mean is over.

    python -m experiments.exp234_retrieval [--n 1000 5000 ...] [--runs 30]
"""

from __future__ import annotations

import argparse
import time

from baselines.common import Prims
from baselines.schemes import Luo31, PlainPRE, Wang25, Yan27
from experiments.harness import quiet, save_machine, services, write_rows
from experiments.workload import World
from rbpre import rbabpre as rb
from rbpre.protocol import Timer

VERIFY_STEPS = ("p4.fetch", "p4.chain_records", "p4.verify_records", "p4.chain_linkage_state",
                "p4.verify_linkage", "p4.merkle_update", "p4.chain_linkage")
# T_ret = T_Map + T_graph + O(k_c (T_Meta + T_policy)) (Eq. 158): admission,
# historical-pseudonym resolution and graph discovery, metadata-opening
# verification and record-level filtering. Verification (Eq. 159) is Exp 4.
RET_STEPS = ("p4.admission", "p4.graph", "p4.filter")


class Series:
    """Run a measurement `runs` times after one discarded warm-up run.

    If the warm-up already takes longer than heavy_s, the series is heavy: the
    warm-up counts as the first measured run (these series are long,
    CPU-bound and stable) and the series stops at runs_heavy runs. Every run is
    timed without garbage-collector pauses (harness.quiet).
    """

    def __init__(self, runs: int, runs_heavy: int, heavy_s: float):
        self.runs, self.runs_heavy, self.heavy_ms = runs, runs_heavy, heavy_s * 1000

    @staticmethod
    def _once(fn) -> float:
        with quiet():
            t0 = time.perf_counter_ns()
            fn()
            return (time.perf_counter_ns() - t0) / 1e6

    def __call__(self, fn, warmup: bool = True) -> list[float]:
        xs, limit = [], self.runs
        if warmup:
            first = self._once(fn)
            if first > self.heavy_ms:
                xs, limit = [first], min(self.runs, self.runs_heavy)
        while len(xs) < limit:
            xs.append(self._once(fn))
            if len(xs) == 1 and xs[0] > self.heavy_ms:
                limit = min(self.runs, self.runs_heavy)
        return xs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, nargs="+", default=[1000, 5000, 10000, 20000, 30000, 40000, 50000])
    ap.add_argument("--hospitals", type=int, default=5)
    ap.add_argument("--ratio", type=float, default=0.10)
    ap.add_argument("--background", type=float, default=1.0, help="background records per target record")
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--runs-heavy", type=int, default=5)
    ap.add_argument("--heavy-s", type=float, default=60.0)
    ap.add_argument("--m", type=int, default=10)
    ap.add_argument("--t", type=int, default=3, help="threshold of [27]")
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args()
    save_machine()

    ledger, graph, store, cache = services(not args.offline, bucket="ehr-exp234")
    w = World(ledger, graph, store, cache, hospitals=args.hospitals, m=args.m)
    s, doc = w.s, w.doc
    target = w.new_target()
    pr = Prims()
    base = [Wang25(pr, ledger), Yan27(pr, ledger, m=args.m, t=args.t), Luo31(pr, ledger)]
    base[2].bind(doc.did)
    pre = PlainPRE(s.scheme, s.kms, pr, ledger)
    p_b = f"{rb.id_attr(doc.did)} AND {doc.attrs[0]}"
    ser = Series(args.runs, args.runs_heavy, args.heavy_s)
    e2, e2s, e3, e4 = [], [], [], []

    def rows(table, scheme, variant, n, xs, **kw):
        for r, ms in enumerate(xs):
            table.append(dict(scheme=scheme, variant=variant, n=n, run=r, ms=ms, runs=len(xs), **kw))

    for n in args.n:
        t_build = time.perf_counter()
        w.grow(target, n, args.ratio)
        bg_have = len(w.index) - target.n
        if bg_have < args.background * n:
            w.add_background(int(args.background * n) - bg_have)
        print(f"N={n}: workload ready in {time.perf_counter() - t_build:.0f} s "
              f"(index {len(w.index)} records)")

        # first retrieval at this size: creates the new linkage entries
        sess = s.authorize(doc, target.patient, "treatment", "cardiology")
        t = Timer()
        t_auth = s.discover(sess, t)
        rows(e2, "RBPRE-CALX", "first", n, [t.total()], t_auth=len(t_auth))
        assert {c["rid"] for c in t_auth} == target.authorized, "T_auth differs from ground truth"
        auth_set = {c["rid"] for c in t_auth}
        t_f_set = {c["rid"] for c in s.last_candidates if c["auth"]}

        # ---------------------------------------------------------- RBPRE-CALX
        sizes, run = {}, [0]

        def rbpre_round(record: bool = True):
            r = run[0]
            se = s.authorize(doc, target.patient, "treatment", "cardiology")
            tt = Timer()
            ta = s.discover(se, tt)
            miss = Timer()
            out = s.transform(se, ta, miss)
            hit = Timer()
            s.transform(se, ta, hit)
            s.pending_anchors.clear()
            sizes.update(t_d=len(s.last_candidates), t_auth=len(ta))
            if not record:  # warm-up
                return
            run[0] += 1
            e2s.extend(dict(n=n, run=r, step=k, ms=v) for k, v in tt.ms.items())
            t_ret = sum(v for k, v in tt.ms.items() if k.startswith(RET_STEPS))
            e2.append(dict(scheme="RBPRE-CALX", variant="filtered", n=n, run=r, ms=t_ret,
                           t_d=len(s.last_candidates), t_auth=len(ta)))
            e2.append(dict(scheme="RBPRE-CALX", variant="with verification", n=n, run=r, ms=tt.total(),
                           t_d=len(s.last_candidates), t_auth=len(ta)))
            e4.append(dict(scheme="RBPRE-CALX", variant="filtered", n=n, verified=len(t_f_set), run=r,
                           ms=sum(tt.ms.get(k, 0.0) for k in VERIFY_STEPS)))
            for variant, tm in (("rk-miss", miss), ("rk-hit", hit)):
                e3.append(dict(scheme="RBPRE-CALX", variant=variant, n=n, run=r, ms=tm.total(),
                               records=len(out)))

        Series._once(lambda: rbpre_round(record=False))
        ser(rbpre_round, warmup=False)
        for table in (e2, e3, e4):  # number of runs behind each RBPRE-CALX mean
            for x in table:
                if x["scheme"] == "RBPRE-CALX" and x["n"] == n and x.get("variant") != "first":
                    x["runs"] = run[0]
        print(f"  RBPRE-CALX: |T_D|={sizes['t_d']} |T_auth|={sizes['t_auth']}")

        # ------------------------------------------------------------ baselines
        pat_entries = [e for e in w.index if e.owner == target.owner]
        auth_entries = [e for e in pat_entries if e.rid in auth_set]
        tf_entries = [e for e in pat_entries if e.rid in t_f_set]
        for b in base:
            rows(e2, b.name, "all", n, ser(lambda: b.retrieve(w.index, target.owner)))
            rows(e2, b.name, "filtered", n, ser(lambda: b.retrieve(w.index, target.owner, auth_set)))
            rows(e3, b.name, "all", n, ser(lambda: b.transform(pat_entries)), records=len(pat_entries))
            rows(e3, b.name, "filtered", n, ser(lambda: b.transform(auth_entries)), records=len(auth_entries))
            if hasattr(b, "verify"):
                rows(e4, b.name, "filtered", n, ser(lambda: b.verify(tf_entries)), verified=len(tf_entries))
            print(f"  {b.name} done")
        # PRE: needs the real ciphertexts
        uris = {r["rid"]: r["uri"] for r in s.graph.candidates(list(s.cs_pids[target.patient.pid]))}
        rids = list(target.rids)
        blobs = dict(zip(rids, store.get_many([uris[r] for r in rids])))
        items = [dict(rid=r, hosp=s.cs_open_r[r]["meta"]["hosp"], ct=blobs[r], open=s.cs_open_r[r])
                 for r in rids]

        def pre_transform(subset):
            sel = [dict(c, ct_k=s.scheme.loads(c["ct"][1])) for c in items if subset is None or c["rid"] in subset]
            pre.transform(sel, doc.pk_bytes, p_b, sess.chi)

        rows(e2, "PRE", "all", n, ser(lambda: pre.retrieve(w.index, target.owner)))
        rows(e2, "PRE", "filtered", n, ser(lambda: pre.retrieve(w.index, target.owner, auth_set)))
        rows(e3, "PRE", "all", n, ser(lambda: pre_transform(None)), records=len(items))
        rows(e3, "PRE", "filtered", n, ser(lambda: pre_transform(auth_set)), records=len(auth_set))
        rows(e4, "PRE", "filtered", n, ser(lambda: pre.verify([c for c in items if c["rid"] in t_f_set])),
             verified=len(t_f_set))
        print("  PRE done")
        write_rows("e2_runs.csv", e2)
        write_rows("e2_steps.csv", e2s)
        write_rows("e3_runs.csv", e3)
        write_rows("e4_runs.csv", e4)

    w.close()
    store.clear()


if __name__ == "__main__":
    main()

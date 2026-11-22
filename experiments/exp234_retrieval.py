#!/usr/bin/env python3
"""Experiments 2-4 on one growing patient history.

  Exp 2  longitudinal retrieval latency vs N linked records: RBPRE-CALX
         T_ret of Eq. 158 (admission, historical-pseudonym resolution, graph
         discovery, metadata-opening verification and record-level filtering);
         the whole of Phase 4 including verification is also kept, as variant
         "with verification". Baselines locate the patient's records with
         one indexed query per hospital repository (Neo4j, the server that
         holds RBPRE-CALX's graph; --repo memory scans an in-memory list
         instead), then run their own per-record validation.
  Exp 3  cross-domain transformation cost vs N: RBPRE-CALX Phase 5 on T_auth,
         with a re-key cache miss (new session) and hit (same session);
         baselines transform every patient record.
  Exp 4  verification overhead vs the number of verified records |T_f|.

In Exps 3 and 4 every scheme reads the ciphertexts it transforms or verifies
from the same MinIO store with the same call (store.get_many), as
RBPRE-CALX's proxy (p5.proxy_fetch) and verifier (p4.fetch) do, so storage
reads are counted for all schemes alike.

Every baseline series is run twice: on all of the patient's records, and
filter-equalized (handed T_auth, or T_f for Exp 4).

A series whose first run at a point takes longer than --heavy-s seconds is
capped at --runs-heavy runs for that point; the CSV records how many runs
each mean is over (within its batch).

Top-up runs (RBPRE_TOPUP set, see harness): --measure-n builds the workload
through every --n exactly as the original run did (same seed, same order) but
measures only at the listed sizes, and --only restricts the measured series
to tokens table:scheme:variant[:n], e.g. e2:PRE:filtered:5000 or e3:[27]:*.

    python -m experiments.exp234_retrieval [--n 1000 5000 ...] [--runs 30]
"""

from __future__ import annotations

import argparse
import time

from baselines.common import Prims
from baselines.repository import DBRepository
from baselines.schemes import Luo31, PlainPRE, Wang25, Yan27
from experiments.harness import quiet, save_machine, selected, services, write_rows
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
    ap.add_argument("--measure-n", type=int, nargs="*", help="measure only at these N (the workload still grows through --n)")
    ap.add_argument("--only", nargs="*", help="measure only these series: table:scheme:variant[:n]")
    ap.add_argument("--repo", choices=("db", "memory"), default="db",
                    help="compared schemes' repository: Neo4j, one indexed query per hospital (db), "
                         "or an in-memory list scan (memory)")
    args = ap.parse_args()
    save_machine()

    def want(table, scheme, variant, n):
        return selected(args.only, table, scheme, variant, n)

    ledger, graph, store, cache = services(not args.offline, bucket="ehr-exp234")
    w = World(ledger, graph, store, cache, hospitals=args.hospitals, m=args.m)
    s, doc = w.s, w.doc
    target = w.new_target()
    pr = Prims()
    base = [Wang25(pr, ledger), Yan27(pr, ledger, m=args.m, t=args.t), Luo31(pr, ledger)]
    base[2].bind(doc.did)
    pre = PlainPRE(s.scheme, s.kms, pr, ledger)
    p_b = f"{rb.id_attr(doc.did)} AND {doc.attrs[0]}"
    repo = DBRepository() if args.repo == "db" else None
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
              f"(index {len(w.index)} records, |T_auth| {len(target.authorized)})")
        if args.measure_n and n not in args.measure_n:
            continue
        if repo is not None:
            repo.sync(w.index)          # the compared schemes' repositories (untimed)
        index = repo if repo is not None else w.index

        # first retrieval at this size: creates the new linkage entries
        sess = s.authorize(doc, target.patient, "treatment", "cardiology")
        t = Timer()
        t_auth = s.discover(sess, t)
        if want("e2", "RBPRE-CALX", "first", n):
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
            # transformation is timed by wall clock, like the compared schemes (Exp 3)
            miss, t0 = Timer(), time.perf_counter_ns()
            out = s.transform(se, ta, miss)
            miss_ms = (time.perf_counter_ns() - t0) / 1e6
            hit, t0 = Timer(), time.perf_counter_ns()
            s.transform(se, ta, hit)
            hit_ms = (time.perf_counter_ns() - t0) / 1e6
            s.pending_anchors.clear()
            sizes.update(t_d=len(s.last_candidates), t_auth=len(ta))
            if not record:  # warm-up
                return
            run[0] += 1
            e2s.extend(dict(n=n, run=r, step=k, ms=v) for k, v in tt.ms.items())
            t_ret = sum(v for k, v in tt.ms.items() if k.startswith(RET_STEPS))
            if want("e2", "RBPRE-CALX", "filtered", n):
                e2.append(dict(scheme="RBPRE-CALX", variant="filtered", n=n, run=r, ms=t_ret,
                               t_d=len(s.last_candidates), t_auth=len(ta)))
            if want("e2", "RBPRE-CALX", "with verification", n):
                e2.append(dict(scheme="RBPRE-CALX", variant="with verification", n=n, run=r, ms=tt.total(),
                               t_d=len(s.last_candidates), t_auth=len(ta)))
            if want("e4", "RBPRE-CALX", "filtered", n):
                e4.append(dict(scheme="RBPRE-CALX", variant="filtered", n=n, verified=len(t_f_set), run=r,
                               ms=sum(tt.ms.get(k, 0.0) for k in VERIFY_STEPS)))
            for variant, ms in (("rk-miss", miss_ms), ("rk-hit", hit_ms)):
                if want("e3", "RBPRE-CALX", variant, n):
                    e3.append(dict(scheme="RBPRE-CALX", variant=variant, n=n, run=r, ms=ms,
                                   records=len(out)))

        rb_series = [("e2", "filtered"), ("e2", "with verification"), ("e3", "rk-miss"), ("e3", "rk-hit"),
                     ("e4", "filtered")]
        if any(want(tb, "RBPRE-CALX", v, n) for tb, v in rb_series):
            Series._once(lambda: rbpre_round(record=False))
            ser(rbpre_round, warmup=False)
            for table in (e2, e3, e4):  # number of runs behind each RBPRE-CALX mean
                for x in table:
                    if x["scheme"] == "RBPRE-CALX" and x["n"] == n and x.get("variant") != "first":
                        x["runs"] = run[0]
            print(f"  RBPRE-CALX: |T_D|={sizes['t_d']} |T_auth|={sizes['t_auth']}")

        # ------------------------------------------------------------ baselines
        # Every scheme reads the ciphertexts it transforms or verifies from the same MinIO store, with the
        # same client call RBPRE-CALX's proxy (p5.proxy_fetch) and verifier (p4.fetch) use.
        uris = {r["rid"]: r["uri"] for r in s.graph.candidates(list(s.cs_pids[target.patient.pid]))}

        def fetch(rids):
            return store.get_many([uris[r] for r in rids])

        pat_entries = [e for e in w.index if e.owner == target.owner]
        auth_entries = [e for e in pat_entries if e.rid in auth_set]
        tf_entries = [e for e in pat_entries if e.rid in t_f_set]
        for b in base:
            if want("e2", b.name, "all", n):
                rows(e2, b.name, "all", n, ser(lambda: b.retrieve(index, target.owner)))
            if want("e2", b.name, "filtered", n):
                rows(e2, b.name, "filtered", n, ser(lambda: b.retrieve(index, target.owner, auth_set)))
            if want("e3", b.name, "all", n):
                rows(e3, b.name, "all", n, ser(lambda: (fetch([e.rid for e in pat_entries]), b.transform(pat_entries))),
                     records=len(pat_entries))
            if want("e3", b.name, "filtered", n):
                rows(e3, b.name, "filtered", n,
                     ser(lambda: (fetch([e.rid for e in auth_entries]), b.transform(auth_entries))),
                     records=len(auth_entries))
            if hasattr(b, "verify") and want("e4", b.name, "filtered", n):
                rows(e4, b.name, "filtered", n, ser(lambda: (fetch([e.rid for e in tf_entries]), b.verify(tf_entries))),
                     verified=len(tf_entries))
            print(f"  {b.name} done")
        # PRE works on the real ciphertexts it reads from the store
        if want("e2", "PRE", "all", n):
            rows(e2, "PRE", "all", n, ser(lambda: pre.retrieve(index, target.owner)))
        if want("e2", "PRE", "filtered", n):
            rows(e2, "PRE", "filtered", n, ser(lambda: pre.retrieve(index, target.owner, auth_set)))

        def pre_items(rids):
            return [dict(rid=r, hosp=s.cs_open_r[r]["meta"]["hosp"], ct=blob, open=s.cs_open_r[r])
                    for r, blob in zip(rids, fetch(rids))]

        def pre_transform(subset):
            rids = [r for r in target.rids if subset is None or r in subset]
            sel = [dict(c, ct_k=s.scheme.loads(c["ct"][1])) for c in pre_items(rids)]
            pre.transform(sel, doc.pk_bytes, p_b, sess.chi)

        if want("e3", "PRE", "all", n):
            rows(e3, "PRE", "all", n, ser(lambda: pre_transform(None)), records=len(target.rids))
        if want("e3", "PRE", "filtered", n):
            rows(e3, "PRE", "filtered", n, ser(lambda: pre_transform(auth_set)), records=len(auth_set))
        if want("e4", "PRE", "filtered", n):
            rows(e4, "PRE", "filtered", n,
                 ser(lambda: pre.verify(pre_items([r for r in target.rids if r in t_f_set]))), verified=len(t_f_set))
        print("  PRE done")
        write_rows("e2_runs.csv", e2)
        write_rows("e2_steps.csv", e2s)
        write_rows("e3_runs.csv", e3)
        write_rows("e4_runs.csv", e4)

    if repo is not None:
        repo.clear()
        repo.close()
    w.close()
    store.clear()


if __name__ == "__main__":
    main()

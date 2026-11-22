#!/usr/bin/env python3
"""Add runs to the unstable points of a finished run, so they average with the
runs already there. Nothing is re-run or discarded.

    python -m experiments.topup --run <name> [--rounds 2] [--ci 0.05] [--max-runs 30] [--dry]

Each round:
  1. experiments.stability finds the points whose 95% CI half-width exceeds
     --ci of the mean (or that kink), with the total run count each needs.
  2. For every driver it starts the extra runs with RBPRE_TOPUP=t<round>,
     so the drivers append rows (batch t<round>) to the existing files.
     Workloads are rebuilt through the original sweep (same seed, same
     order) and only the unstable points are measured.
No point goes past --max-runs runs. The next round re-checks with the new
SDs. Per-step logs: results/<run>/logs/topup-t<round>-<step>.log; start, end
and status go to progress.log. --dry prints the plan only.
"""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from experiments.stability import check, report

ROOT = Path(__file__).resolve().parent.parent
E7_VARIANTS = ["full", "(i) no reuse", "(ii) no early filter", "(iii) no selective PRE",
               "(iv) no filter + no selective"]


def column(out: Path, table: str, col: str) -> list[str]:
    with (out / f"{table}.csv").open() as f:
        return list(dict.fromkeys(r[col] for r in csv.DictReader(f) if r.get(col)))


def num(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else f"{v:g}"


def plan(out: Path, flagged: list[dict], runs_heavy: int) -> list[tuple[str, list[str]]]:
    by = defaultdict(list)
    for f in flagged:
        if f["runs_needed"] > f["runs"]:
            by[f["table"]].append(f)
    extra = lambda fs: max(f["runs_needed"] - f["runs"] for f in fs)  # noqa: E731
    steps = []
    if by["e1a_runs"]:
        fs = by["e1a_runs"]
        steps.append(("exp1a", ["experiments.exp1_authz", "--parts", "a", "--runs", str(extra(fs)),
                                "--m", *sorted({num(f["x"]) for f in fs}, key=int)]))
    ks = defaultdict(list)
    for f in by["e1b_runs"] + by["e1g_runs"]:  # one Exp 1 (b) run measures both tables
        ks[int(f["x"])].append(f)
    for k in sorted(ks):  # one invocation per k, each with the runs that k needs
        steps.append((f"exp1b-k{k}", ["experiments.exp1_authz", "--parts", "b", "--k", str(k),
                                      "--runs", str(extra(ks[k]))]))
    fs = by["e2_runs"] + by["e3_runs"] + by["e4_runs"]
    if fs:
        toks, ns = [], set()
        for f in fs:
            n = int(f["x"]) if f["table"] != "e4_runs" else f["n"]
            scheme, variant = f["key"]
            toks.append(f"{f['table'][:2]}:{scheme}:{variant}:{n}")
            ns.add(n)
        steps.append(("exp234", ["experiments.exp234_retrieval", "--runs", str(extra(fs)),
                                 "--runs-heavy", str(runs_heavy),
                                 "--n", *sorted(column(out, "e2_runs", "n"), key=int),
                                 "--measure-n", *map(str, sorted(ns)), "--only", *dict.fromkeys(toks)]))
    fs = by["e7_runs"]
    if fs:
        steps.append(("exp7", ["experiments.exp7_ablation", "--runs", str(extra(fs)),
                               "--n", column(out, "e7_runs", "n")[0],
                               "--ratios", *column(out, "e7_runs", "ratio"),
                               "--measure-ratios", *sorted({num(f["x"]) for f in fs}, key=float),
                               "--variants", *sorted({str(E7_VARIANTS.index(f["key"][0])) for f in fs})]))
    # revocation: one RBPRE-CALX run measures every event at a point (N, S) and is long, so each
    # point gets its own invocation with only the runs it needs; the compared schemes go together
    pts = defaultdict(list)
    for f in by["erev_runs"]:
        scheme, _event, sessions = f["key"]
        tok = f"{scheme}:{int(f['x'])}:{sessions}" if scheme == "RBPRE-CALX" else f"{scheme}:{int(f['x'])}"
        pts[tok if scheme == "RBPRE-CALX" else "baselines"].append((tok, f))
    ns_all = sorted((int(v) for v in column(out, "erev_runs", "n")) if pts else [])
    sessions = sorted(column(out, "erev_runs", "sessions"), key=int) if pts else []
    for key in sorted(pts, key=lambda k: (k == "baselines", k)):
        toks, fs = list(dict.fromkeys(t for t, _ in pts[key])), [f for _, f in pts[key]]
        top = max(int(f["x"]) for f in fs)  # the history grows in order, so stop at the largest measured N
        name = "revocation-" + ("baselines" if key == "baselines" else "n{}-s{}".format(*key.split(":")[1:]))
        steps.append((name, ["experiments.exp_revocation", "--runs", str(extra(fs)),
                             "--n", *[str(v) for v in ns_all if v <= top], "--sessions", *sessions, "--only", *toks]))
    return steps


def log(out: Path, msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    with (out / "progress.log").open("a") as f:
        f.write(line + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default=os.environ.get("RBPRE_RUN", "dev"))
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--ci", type=float, default=0.05)
    ap.add_argument("--max-runs", type=int, default=30)
    ap.add_argument("--runs-heavy", type=int, default=3)
    ap.add_argument("--first-round", type=int, default=1, help="label of the first round (t<first-round>)")
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()
    out = ROOT / "results" / args.run
    (out / "logs").mkdir(exist_ok=True)
    for rnd in range(args.first_round, args.first_round + args.rounds):
        flagged = check(out, args.ci, args.max_runs)
        steps = plan(out, flagged, args.runs_heavy)
        if not steps:
            break
        label = f"t{rnd}"
        if args.dry:
            report(out, flagged, args.ci)
            for name, argv in steps:
                print(f"[{label}] {name}: python -m {' '.join(repr(a) if ' ' in a else a for a in argv)}")
            return
        log(out, f"topup {label}: {len(flagged)} unstable points, {len(steps)} steps")
        env = dict(os.environ, RBPRE_RUN=args.run, RBPRE_TOPUP=label)
        for name, argv in steps:
            log(out, f"start topup-{label}-{name}: {' '.join(argv)}")
            t0 = time.time()
            with (out / "logs" / f"topup-{label}-{name}.log").open("w") as fh:
                rc = subprocess.run([sys.executable, "-u", "-m", *argv], cwd=ROOT, env=env, stdout=fh,
                                    stderr=subprocess.STDOUT).returncode
            status = "done " if rc == 0 else f"FAIL (exit {rc})"
            log(out, f"{status} topup-{label}-{name} ({(time.time() - t0) / 60:.0f} min)")
    flagged = check(out, args.ci, args.max_runs)
    log(out, f"topup finished: {len(flagged)} points still above ±{100 * args.ci:.0f}% "
             f"(at most {args.max_runs} runs each)")
    report(out, flagged, args.ci)


if __name__ == "__main__":
    main()

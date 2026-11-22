#!/usr/bin/env python3
"""Which plotted points are not yet stable, and how many runs they need.

    python -m experiments.stability [--run <name>] [--ci 0.05] [--max-runs 30]

For every point of every figure (the same grouping the plots use) it computes
the mean, the SD and the half-width of the 95% confidence interval of the
mean. A point is unstable when that half-width exceeds --ci of the mean, or
when its mean lies on the wrong side of a neighbouring point on a curve that
should rise with x (a visible kink). For each unstable point it prints how
many runs in total would bring the half-width under --ci at the observed
SD, capped at --max-runs. Points measured once (e.g. "first") are skipped.
It only reads CSV files.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# two-sided 95% Student t quantiles, df = 1..30
T95 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145,
       2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048,
       2.045, 2.042]


def t95(df: int) -> float:
    return T95[df - 1] if df <= len(T95) else 1.96 + 2.4 / df


# table -> (series key columns, x column, value column, curve rises with x)
TABLES = {
    "e1a_runs": (("circuit",), "m", "prove_ms", True),
    "e1b_runs": (("scheme", "variant"), "k", "total_ms", True),
    "e1g_runs": (("scheme", "variant"), "k", "gateway_ms", True),
    "e2_runs": (("scheme", "variant"), "n", "ms", True),
    "e3_runs": (("scheme", "variant"), "n", "ms", True),
    "e4_runs": (("scheme", "variant"), "verified", "ms", True),
    "e6_runs": (("scheme", "variant"), "hospitals", "ms", False),
    "e5_runs": (("scheme",), "events", "ms", True),
    "e7_runs": (("variant",), "ratio", "ms", False),
    "erev_runs": (("scheme", "event", "sessions"), "n", "ms", False),
}


def needed(cv: float, ci: float, cap: int) -> int:
    n = 2
    while n < cap and t95(n - 1) * cv / math.sqrt(n) > ci:
        n += 1
    return n


def check(out: Path, ci: float, cap: int) -> list[dict]:
    flagged = []
    for name, (keys, x, val, rising) in TABLES.items():
        p = out / f"{name}.csv"
        if not p.exists():
            continue
        groups = defaultdict(lambda: defaultdict(list))
        n_of = {}  # x -> patient size N, for tables whose x is not N (e4: verified records)
        with p.open() as f:
            for r in csv.DictReader(f):
                if r.get("variant") == "first":
                    continue
                groups[tuple(r[k] for k in keys)][float(r[x])].append(float(r[val]))
                if r.get("n"):
                    n_of[float(r[x])] = int(float(r["n"]))
        for k, pts in groups.items():
            xs = sorted(pts)
            st = {}
            for v in xs:
                ys = pts[v]
                m = statistics.fmean(ys)
                sd = statistics.stdev(ys) if len(ys) > 1 else 0.0
                hw = t95(len(ys) - 1) * sd / math.sqrt(len(ys)) if len(ys) > 1 else float("nan")
                st[v] = (m, sd, len(ys), hw)
            for i, v in enumerate(xs):
                m, sd, n, hw = st[v]
                if n < 2:
                    continue
                why = []
                if hw > ci * m:
                    why.append(f"CI ±{100 * hw / m:.1f}%")
                if rising:
                    for j in (i - 1, i + 1):
                        if 0 <= j < len(xs):
                            m2, _, _, hw2 = st[xs[j]]
                            if (j < i and m < m2) or (j > i and m > m2):
                                why.append(f"kink vs x={xs[j]:g}")
                if why:
                    need = max(n, needed(sd / m if m else 0, ci, cap))
                    if any(w_.startswith("kink") for w_ in why):  # a kink with a tight CI still gets more runs
                        need = max(need, min(cap, n + 10))
                    flagged.append(dict(table=name, series=" / ".join(k), x=v, runs=n, mean_ms=round(m, 3),
                                        sd_ms=round(sd, 3), ci_pct=round(100 * hw / m, 1), runs_needed=need,
                                        why="; ".join(why), key=k, n=n_of.get(v)))
    return flagged


PUBLIC = ("table", "series", "x", "runs", "mean_ms", "sd_ms", "ci_pct", "runs_needed", "why")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default=os.environ.get("RBPRE_RUN", "dev"))
    ap.add_argument("--ci", type=float, default=0.05, help="max 95%% CI half-width, as a fraction of the mean")
    ap.add_argument("--max-runs", type=int, default=30)
    args = ap.parse_args()
    out = ROOT / "results" / args.run
    flagged = check(out, args.ci, args.max_runs)
    report(out, flagged, args.ci)


def report(out: Path, flagged: list[dict], ci: float) -> None:
    with (out / "stability.csv").open("w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=PUBLIC, extrasaction="ignore")
        wr.writeheader()
        wr.writerows(flagged)
    if not flagged:
        print(f"{out.name}: every point is stable (95% CI within ±{100 * ci:.0f}% of the mean, no kinks)")
        return
    w = max(len(f["series"]) for f in flagged)
    for f in flagged:
        print(f"{f['table']:<10} {f['series']:<{w}}  x={f['x']:<8g} runs={f['runs']:<3} "
              f"mean={f['mean_ms']:>11.1f} sd={f['sd_ms']:>9.1f}  -> {f['runs_needed']:>2} runs  ({f['why']})")


if __name__ == "__main__":
    main()

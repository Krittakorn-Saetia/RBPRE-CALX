#!/usr/bin/env python3
"""Figures and summary tables from results/<run>/*.csv (it never generates data).

    python -m experiments.plot [--run <name>]

Needs matplotlib. For every figure it writes results/<run>/fig/<name>.png
and .pdf, plus results/<run>/summary_<name>.csv with mean, SD and run count
per point (the table view of the figure). For Experiment 7 it writes
e7_welch.csv: Welch's t-test between variants (iii) and (iv) at each ratio.

Colour follows the scheme: RBPRE-CALX, [25], [27], [31], PRE take categorical
slots 1-5 in that order, each with its own marker. Line style carries the
variant: solid = all records, dashed = filter-equalized (handed T_auth), and
dotted = re-key cache hit.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SLOTS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
MARKERS = ["o", "s", "^", "D", "v", "P", "X", "*"]
SCHEMES = ["RBPRE-CALX", "[25]", "[27]", "[31]", "PRE"]
INK, INK2, GRID, AXIS = "#0b0b0b", "#52514e", "#e1e0d9", "#c3c2b7"
STYLE = {"all": "-", "filtered": "--", "rk-miss": "-", "rk-hit": ":", "first": "-."}

plt.rcParams.update({
    "font.family": "sans-serif", "font.size": 9, "axes.edgecolor": AXIS, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False, "figure.dpi": 150,
    "savefig.bbox": "tight", "lines.linewidth": 1.6, "lines.markersize": 6,
})


def load(out: Path, name: str) -> list[dict]:
    p = out / f"{name}.csv"
    if not p.exists():
        return []
    with p.open() as f:
        return list(csv.DictReader(f))


def stats(xs):
    return statistics.fmean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0.0), len(xs)


def color(scheme: str) -> tuple[str, str]:
    i = SCHEMES.index(scheme) if scheme in SCHEMES else len(SCHEMES)
    return SLOTS[i % len(SLOTS)], MARKERS[i % len(MARKERS)]


def save(fig, out: Path, name: str, summary: list[dict]) -> None:
    d = out / "fig"
    d.mkdir(exist_ok=True)
    fig.savefig(d / f"{name}.png")
    fig.savefig(d / f"{name}.pdf")
    plt.close(fig)
    if summary:
        with (out / f"summary_{name}.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(summary[0]))
            w.writeheader()
            w.writerows(summary)
    print(f"  {name}")


def series_plot(out, name, rows, x, title, xlabel, ylabel="latency (ms)", logy=True, key=("scheme", "variant"),
                label=None, order=None):
    groups = defaultdict(lambda: defaultdict(list))
    for r in rows:
        groups[tuple(r[k] for k in key)][float(r[x])].append(float(r["ms"]))
    fig, ax = plt.subplots(figsize=(4.6, 3.2))
    summary = []
    keys = sorted(groups, key=lambda k: ((order or SCHEMES).index(k[0]) if k[0] in (order or SCHEMES) else 99,
                                         list(STYLE).index(k[1]) if len(k) > 1 and k[1] in STYLE else 9))
    for i, k in enumerate(keys):
        xs = sorted(groups[k])
        m = [stats(groups[k][v]) for v in xs]
        if order:
            c, mk = SLOTS[order.index(k[0]) % len(SLOTS)], MARKERS[order.index(k[0]) % len(MARKERS)]
        else:
            c, mk = color(k[0])
        ls = STYLE.get(k[1], "-") if len(k) > 1 else "-"
        lab = label(k) if label else " ".join(k)
        ax.errorbar(xs, [a for a, _, _ in m], yerr=[s for _, s, _ in m], color=c, ls=ls, marker=mk,
                    markeredgecolor="white", markeredgewidth=0.8, capsize=2, elinewidth=0.7, label=lab)
        summary += [dict(series=lab, x=v, mean_ms=a, sd_ms=s, runs=n) for v, (a, s, n) in zip(xs, m)]
    if logy:
        ax.set_yscale("log")
    ax.set_title(title, color=INK, fontsize=10, loc="left")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.legend(fontsize=7, ncol=2, loc="upper center", bbox_to_anchor=(0.5, -0.2))
    save(fig, out, name, summary)


def label_variant(k):
    scheme, variant = k
    if scheme == "RBPRE-CALX":
        return {"filtered": "RBPRE-CALX", "rk-miss": "RBPRE-CALX (re-key miss)",
                "rk-hit": "RBPRE-CALX (re-key hit)", "first": "RBPRE-CALX (first, new linkage)"}.get(variant, scheme)
    return f"{scheme} ({'all records' if variant == 'all' else 'given T_auth'})"


def welch(a, b):
    """Welch's t-test; returns (t, df, two-sided p)."""
    ma, sa, na = stats(a)
    mb, sb, nb = stats(b)
    va, vb = sa * sa / na, sb * sb / nb
    if va + vb == 0:
        return float("nan"), float("nan"), float("nan")
    t = (ma - mb) / math.sqrt(va + vb)
    df = (va + vb) ** 2 / ((va * va / (na - 1) if na > 1 else 0) + (vb * vb / (nb - 1) if nb > 1 else 0) or 1e-300)
    return t, df, _betainc(df / 2, 0.5, df / (df + t * t))


def _betainc(a, b, x):
    """Regularized incomplete beta I_x(a, b) (continued fraction)."""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1 - x)
    if x > (a + 1) / (a + b + 2):
        return 1 - _betainc(b, a, 1 - x)
    c, d = 1.0, 1 - (a + b) * x / (a + 1)
    d = 1 / (d if abs(d) > 1e-300 else 1e-300)
    h = d
    for m in range(1, 300):
        for num in (m * (b - m) * x / ((a + 2 * m - 1) * (a + 2 * m)),
                    -(a + m) * (a + b + m) * x / ((a + 2 * m) * (a + 2 * m + 1))):
            d = 1 + num * d
            d = 1 / (d if abs(d) > 1e-300 else 1e-300)
            c = 1 + num / c if abs(1 + num / c) > 1e-300 else 1e-300
            h *= d * c
        if abs(d * c - 1) < 1e-12:
            break
    return math.exp(lbeta) * h / a


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default=os.environ.get("RBPRE_RUN", "dev"))
    out = ROOT / "results" / ap.parse_args().run
    print(f"figures for {out}")

    rows = load(out, "e1a_setup")
    if rows:
        fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.2, 3.0))
        runs = load(out, "e1a_runs")
        summary = []
        for i, circuit in enumerate(("holder", "original")):
            pts = sorted((int(r["m"]), int(r["constraints"])) for r in rows if r["circuit"] == circuit)
            a1.plot([p[0] for p in pts], [p[1] for p in pts], color=SLOTS[i], marker=MARKERS[i],
                    markeredgecolor="white", label=f"{circuit} R_auth")
            by_m = defaultdict(list)
            for r in runs:
                if r["circuit"] == circuit:
                    by_m[int(r["m"])].append(float(r["prove_ms"]))
            ms = sorted(by_m)
            st = [stats(by_m[m]) for m in ms]
            a2.errorbar(ms, [s[0] for s in st], yerr=[s[1] for s in st], color=SLOTS[i], marker=MARKERS[i],
                        markeredgecolor="white", capsize=2, label=f"{circuit} R_auth")
            summary += [dict(circuit=circuit, m=m, constraints=c, prove_mean_ms=s[0], prove_sd_ms=s[1], runs=s[2])
                        for (m, c), s in zip(pts, st)]
        a1.set_title("R1CS constraints", color=INK, fontsize=10, loc="left")
        a2.set_title("proof generation (ms)", color=INK, fontsize=10, loc="left")
        for a in (a1, a2):
            a.set_xlabel("policy attributes m")
            a.legend(fontsize=7)
        save(fig, out, "e1a_circuits", summary)

    rows = load(out, "e1b_runs")
    if rows:
        for r in rows:
            r["ms"] = r["total_ms"]
            r["series"] = r["scheme"]
        series_plot(out, "e1b_authorization", rows, "k", "Cumulative authorization latency", "requests k",
                    key=("series",), order=["RBPRE-CALX Fresh", "RBPRE-CALX Reuse", "[25]", "[27]", "[31]"],
                    label=lambda k: k[0])

    for name, fname, x, title, xl in (
            ("e2_runs", "e2_retrieval", "n", "Longitudinal retrieval latency", "linked EHR records N"),
            ("e3_runs", "e3_transformation", "n", "Cross-domain transformation cost", "linked EHR records N"),
            ("e4_runs", "e4_verification", "verified", "Retrieval verification overhead", "verified records"),
            ("e6_runs", "e6_hospitals", "hospitals", "End-to-end retrieval vs hospitals", "hospitals H")):
        rows = load(out, name)
        if rows:
            series_plot(out, fname, rows, x, title, xl, label=label_variant)

    rows = load(out, "e5_runs")
    if rows:
        for r in rows:
            r["variant"] = "all"
        series_plot(out, "e5_traceability", rows, "events", "Blockchain traceability (until committed)",
                    "audit events", key=("scheme",), label=lambda k: k[0])

    rows = load(out, "e7_runs")
    if rows:
        order = ["full", "(i) no reuse", "(ii) no early filter", "(iii) no selective PRE",
                 "(iv) no filter + no selective"]
        for r in rows:
            r["ratio_pct"] = float(r["ratio"]) * 100
        series_plot(out, "e7_ablation", rows, "ratio_pct", "Ablation: end-to-end retrieval", "|T_auth| / N (%)",
                    key=("variant",), order=order, label=lambda k: k[0])
        wl = []
        for ratio in sorted({r["ratio"] for r in rows}, key=float):
            a = [float(r["ms"]) for r in rows if r["ratio"] == ratio and r["variant"] == order[3]]
            b = [float(r["ms"]) for r in rows if r["ratio"] == ratio and r["variant"] == order[4]]
            if len(a) > 1 and len(b) > 1:
                t, df, p = welch(a, b)
                wl.append(dict(ratio=ratio, mean_iii=stats(a)[0], mean_iv=stats(b)[0], t=t, df=df, p=p))
        if wl:
            with (out / "e7_welch.csv").open("w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(wl[0]))
                w.writeheader()
                w.writerows(wl)

    rows = load(out, "erev_runs")
    if rows:
        ev = defaultdict(list)
        for r in rows:
            if r["scheme"] == "RBPRE-CALX":
                ev[r["event"]].append(float(r["ms"]))
        names = list(ev)
        st = [stats(ev[k]) for k in names]
        fig, ax = plt.subplots(figsize=(5.2, 3.0))
        ax.set_axisbelow(True)
        ax.grid(axis="y", visible=False)
        ax.barh(range(len(names)), [s[0] for s in st], xerr=[s[1] for s in st], color=SLOTS[0], height=0.6,
                edgecolor="white", linewidth=1, error_kw=dict(elinewidth=0.7, capsize=2, ecolor=INK2))
        ax.set_yticks(range(len(names)), names, fontsize=7)
        ax.invert_yaxis()
        ax.set_xlabel("latency (ms), including Fabric finalization")
        ax.set_title("RBPRE-CALX revocation and update events", color=INK, fontsize=10, loc="left")
        save(fig, out, "erev_events", [dict(event=k, mean_ms=s[0], sd_ms=s[1], runs=s[2]) for k, s in zip(names, st)])
        cmp_rows = [dict(r, scheme=r["scheme"], variant="all") for r in rows
                    if r["event"] in ("policy update", "policy update / revocation")]
        series_plot(out, "erev_policy_update", cmp_rows, "n", "Policy update / revocation cost",
                    "patient records N", key=("scheme",), label=lambda k: k[0])


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Figures and summary tables from results/<run>/*.csv (it never generates data).

    python -m experiments.plot [--run <name>]

Needs matplotlib. For every figure it writes results/<run>/fig/<name>.png
(200 dpi) and .pdf, plus results/<run>/summary_<name>.csv with mean, SD and
run count per point (the table view of the figure). For Experiment 7 it
writes e7_welch.csv: Welch's t-test between variants (iii) and (iv) at each
ratio.

The figures follow the format of the manuscript's Figs. 2-8:
- Line charts (Figs. 2-7): matplotlib's default colours and one marker per
  scheme ([25] blue circle, [27] orange square, [31] green triangle,
  RBPRE-CALX red diamond; the new conventional-PRE baseline is purple), a
  full frame, a dashed major and minor grid, a log y-axis labelled
  "(ms, log scale)", evenly spaced x positions labelled with thousands
  separators, a framed legend and no title. Each point is the mean;
  error bars show one standard deviation.
- A second variant of a scheme keeps the scheme's colour and marker, with a
  dashed or dotted line and an open marker (e.g. the filter-equalized run
  "given T_auth", or RBPRE-CALX with a re-key cache hit).
- Bar charts (Fig. 8 and the revocation events): serif text, horizontal
  bars with the label above each bar and the value at its end, full
  framework in blue and the other variants in grey.
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
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# scheme -> (colour, marker), as in the manuscript's Figs. 2-7
SCHEME = {"[25]": ("#1f77b4", "o"), "[27]": ("#ff7f0e", "s"), "[31]": ("#2ca02c", "^"),
          "PRE": ("#9467bd", "v"), "RBPRE-CALX": ("#d62728", "D")}
ORDER = ["[25]", "[27]", "[31]", "PRE", "RBPRE-CALX"]   # legend order: compared schemes, then RBPRE-CALX
NAME = {"[25]": "Scheme [25]", "[27]": "Scheme [27]", "[31]": "Scheme [31]", "PRE": "Conventional PRE",
        "RBPRE-CALX": "RBPRE-CALX"}
TAUTH = r"$T_{\mathrm{auth}}$"
# variant -> (line style, open marker, label suffix); the first entry of each scheme is its main series
VARIANT = {
    "all": ("-", False, ""),
    "filtered": ("--", True, f" (given {TAUTH})"),
    "rk-miss": ("-", False, " (re-key miss)"),
    "rk-hit": ("--", True, " (re-key hit)"),
    "with verification": ("--", True, " (with verification)"),
    "first": (":", True, " (first retrieval)"),
    "Fresh": ("-", False, " (Fresh)"),
    "Reuse 10/session": ("--", True, " (Reuse, 10 requests/session)"),
    "Reuse 50/session": (":", True, " (Reuse, 50 requests/session)"),
    "Reuse all/session": ("-.", True, " (Reuse, one session)"),
}
# RBPRE-CALX's own filtered retrieval/verification is its main series, not a filter-equalized variant
RB_MAIN = {"filtered": ("-", False, "")}
BLUE, GREY, INK, INK2, AXIS = "#2a78d6", "#a8a59e", "#000000", "#4a4a4a", "#c3c2b7"

PAPER_RC = {
    "font.family": "DejaVu Sans", "font.size": 13, "axes.labelsize": 14, "xtick.labelsize": 13,
    "ytick.labelsize": 13, "legend.fontsize": 12, "axes.edgecolor": INK, "axes.linewidth": 1.0,
    "axes.spines.top": True, "axes.spines.right": True, "axes.grid": False, "legend.frameon": True,
    "legend.framealpha": 0.9, "legend.edgecolor": "#cccccc", "lines.linewidth": 2.0, "lines.markersize": 8,
    "figure.dpi": 100, "savefig.dpi": 200, "savefig.bbox": "tight", "savefig.facecolor": "white",
    "errorbar.capsize": 3,
}
BAR_RC = dict(PAPER_RC, **{"font.family": "DejaVu Serif", "axes.spines.top": False, "axes.spines.right": False,
                           "axes.edgecolor": AXIS, "xtick.color": INK2})
COMMA = FuncFormatter(lambda v, _: f"{v:,.0f}")


def load(out: Path, name: str) -> list[dict]:
    p = out / f"{name}.csv"
    if not p.exists():
        return []
    with p.open() as f:
        return list(csv.DictReader(f))


def stats(xs):
    return statistics.fmean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0.0), len(xs)


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


def tick(v: float, pct: bool = False) -> str:
    if pct:
        return f"{v:g}%"
    return f"{v:,.0f}" if float(v).is_integer() else f"{v:,g}"


def paper_axes(ax, logy: bool, xs: list[float], categorical: bool, pct: bool = False):
    if logy:
        ax.set_yscale("log")
    else:
        ax.yaxis.set_major_formatter(COMMA)
    ax.grid(True, which="major", ls="--", lw=0.7, color="#c8c8c8", alpha=0.8)
    if logy:
        ax.grid(True, which="minor", axis="y", ls="--", lw=0.5, color="#dddddd", alpha=0.8)
    ax.set_axisbelow(True)
    if categorical:
        ax.set_xticks(range(len(xs)), [tick(v, pct) for v in xs])
        ax.set_xlim(-0.35, len(xs) - 0.65)
    else:
        ax.set_xticks(xs, [tick(v, pct) for v in xs])


def line_kw(c, mk, ls, hollow):
    return dict(color=c, ls=ls, marker=mk, markerfacecolor="white" if hollow else c, markeredgecolor=c,
                markeredgewidth=1.6 if hollow else 1.0)


def handle(c, mk, ls, hollow, lab):
    """Legend entry with line and marker only (no error-bar glyph), as in the manuscript."""
    return Line2D([0], [0], lw=2.0, ms=8, label=lab, **line_kw(c, mk, ls, hollow))


def series_plot(out, name, rows, x, xlabel, ylabel, logy=True, categorical=True, key=("scheme", "variant"),
                style=None, pct=False, legend_loc="best", hide=()):
    """One line per series key. style(key) -> (colour, marker, line style, open marker, label, order).
    Series whose key is in `hide` are left out of the figure but kept in the summary table."""
    groups = defaultdict(lambda: defaultdict(list))
    for r in rows:
        groups[tuple(r[k] for k in key)][float(r[x])].append(float(r["ms"]))
    allx = sorted({v for k, g in groups.items() if k not in hide for v in g})
    pos = {v: i for i, v in enumerate(allx)} if categorical else {v: v for v in allx}
    with plt.rc_context(PAPER_RC):
        fig, ax = plt.subplots(figsize=(8, 5))
        summary, handles = [], []
        for k in sorted(groups, key=lambda k: style(k)[5]):
            c, mk, ls, hollow, lab, _ = style(k)
            xs = sorted(groups[k])
            m = [stats(groups[k][v]) for v in xs]
            summary += [dict(series=lab.replace(TAUTH, "T_auth"), x=v, mean_ms=a, sd_ms=s, runs=n)
                        for v, (a, s, n) in zip(xs, m)]
            if k in hide:
                continue
            ax.errorbar([pos[v] for v in xs], [a for a, _, _ in m], yerr=[s for _, s, _ in m], elinewidth=1.0,
                        **line_kw(c, mk, ls, hollow))
            handles.append(handle(c, mk, ls, hollow, lab))
        paper_axes(ax, logy, allx, categorical, pct)
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        if len(handles) <= 5:
            ax.legend(handles=handles, loc=legend_loc)
        else:
            ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=2, fontsize=11)
        save(fig, out, name, summary)


def scheme_style(k):
    scheme, variant = k[0], (k[1] if len(k) > 1 else "all")
    c, mk = SCHEME.get(scheme, ("#7f7f7f", "x"))
    table = RB_MAIN if scheme == "RBPRE-CALX" and variant in RB_MAIN else VARIANT
    ls, hollow, suffix = table.get(variant, ("-", False, f" ({variant})"))
    order = (ORDER.index(scheme) if scheme in ORDER else 9) * 20 + list(VARIANT).index(variant) \
        if variant in VARIANT else 99
    return c, mk, ls, hollow, NAME.get(scheme, scheme) + suffix, order


def bar_panel(ax, names, st, colors, base=None):
    """Fig. 8 layout: label above each bar, mean (and change vs `base`) at the bar end."""
    y = list(range(len(names)))
    ax.barh(y, [s[0] for s in st], xerr=[s[1] for s in st], color=colors, height=0.4,
            error_kw=dict(elinewidth=1.4, capsize=4, capthick=1.4, ecolor=INK))
    hi = max(s[0] + s[1] for s in st)
    for i, (nm, (a, sd, _)) in enumerate(zip(names, st)):
        ax.text(0, i - 0.32, nm, ha="left", va="bottom", fontsize=13, color=INK)
        txt = f"{a:,.0f} ms"
        if base is not None and i > 0 and base > 0:
            txt += f" ({100 * (a - base) / base:+.1f}%)"
        ax.text(a + sd + hi * 0.012, i, txt, ha="left", va="center", fontsize=12, color=INK)
    ax.set_yticks([])
    ax.set_ylim(len(names) - 0.5, -0.9)
    ax.set_xlim(0, hi * 1.45)
    ax.xaxis.set_major_formatter(COMMA)
    ax.grid(True, axis="x", color="#dddad2", lw=1.0)
    ax.set_axisbelow(True)


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


E7_ORDER = ["full", "(i) no reuse", "(ii) no early filter", "(iii) no selective PRE", "(iv) no filter + no selective"]
# names as in the revised manuscript's Experiment 7 text
E7_NAME = {"full": "Full RBPRE-CALX", "(i) no reuse": "w/o reusable context",
           "(ii) no early filter": "w/o early filtering", "(iii) no selective PRE": "w/o selective PRE",
           "(iv) no filter + no selective": "w/o early filtering + selective PRE"}
E7_LINE = {"full": ("#d62728", "D", "-"), "(i) no reuse": ("#8c564b", "o", "--"),
           "(ii) no early filter": ("#e377c2", "s", "-."), "(iii) no selective PRE": ("#7f7f7f", "^", ":"),
           "(iv) no filter + no selective": ("#bcbd22", "v", "--")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default=os.environ.get("RBPRE_RUN", "dev"))
    out = ROOT / "results" / ap.parse_args().run
    print(f"figures for {out}")

    # ---------------------------------------------------------------- Exp 1 (a)
    rows = load(out, "e1a_setup")
    if rows:
        runs = load(out, "e1a_runs")
        summary = []
        circ = {"holder": ("#d62728", "D", "-", False, r"Holder-bound $R_{\mathrm{auth}}$ (revised)"),
                "original": ("#7f7f7f", "s", "--", True, r"Original $R_{\mathrm{auth}}$ (first submission)")}
        with plt.rc_context(PAPER_RC):
            fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 5))
            handles = []
            for i, (circuit, (c, mk, ls, hollow, lab)) in enumerate(circ.items()):
                # one point per m (top-up batches repeat the setup rows with the same constraint count)
                pts = sorted({int(r["m"]): int(r["constraints"]) for r in rows if r["circuit"] == circuit}.items())
                kw = line_kw(c, mk, ls, hollow)
                a1.plot([p[0] for p in pts], [p[1] for p in pts], **kw)
                handles.append(handle(c, mk, ls, hollow, lab))
                by_m = defaultdict(list)
                for r in runs:
                    if r["circuit"] == circuit:
                        by_m[int(r["m"])].append(float(r["prove_ms"]))
                ms = sorted(by_m)
                st = [stats(by_m[m]) for m in ms]
                a2.errorbar(ms, [s[0] for s in st], yerr=[s[1] for s in st], elinewidth=1.0, **kw)
                summary += [dict(circuit=circuit, m=m, constraints=cn, prove_mean_ms=s[0], prove_sd_ms=s[1],
                                 runs=s[2]) for (m, cn), s in zip(pts, st)]
                # Groth16 proving runs FFTs over a power-of-two domain >= the constraint count: mark where
                # the domain doubles, which steps the proving time up
                for (m0, c0), (m1, c1) in zip(pts, pts[1:]):
                    if (c0 - 1).bit_length() != (c1 - 1).bit_length() and m1 in by_m:
                        yv = stats(by_m[m1])[0]
                        a2.annotate(f"FFT domain $2^{{{(c1 - 1).bit_length()}}}$\n({c1:,} constraints)",
                                    xy=(m1, yv), xytext=(m1 + 0.8, yv - (40 if i == 0 else 32)),
                                    textcoords="data", ha="left", va="center", fontsize=10.5, color=INK2,
                                    arrowprops=dict(arrowstyle="-", color=INK2, lw=0.8))
            mvals = sorted({int(r["m"]) for r in rows})
            for a, loc in ((a1, "upper left"), (a2, "upper left")):
                paper_axes(a, False, mvals, False)
                a.set_xlabel("Number of policy attributes $m$")
                a.legend(handles=handles, loc=loc, fontsize=11)
            a1.set_ylabel("R1CS constraints")
            a2.set_ylabel("Proof generation time (ms)")
            save(fig, out, "e1a_circuits", summary)

    # ---------------------------------------------------------------- Exp 1 (b)
    rows = load(out, "e1b_runs")
    if rows:
        for r in rows:
            r["ms"] = r["total_ms"]
        series_plot(out, "e1b_authorization", rows, "k", "Number of Requests",
                    "Authentication and Authorization Latency\n(ms, log scale)", style=scheme_style)
    rows = load(out, "e1g_runs")
    if rows:
        for r in rows:
            r["ms"] = r["gateway_ms"]
        series_plot(out, "e1g_gateway", rows, "k", "Number of Requests",
                    "Gateway-side Authorization Cost\n(ms, log scale)", style=scheme_style)

    # ---------------------------------------------------------------- Exps 2-4, 6
    for name, fname, x, xl, yl, logy in (
            ("e2_runs", "e2_retrieval", "n", "Number of Linked EHR Records", "Retrieval Latency (ms, log scale)", True),
            ("e3_runs", "e3_transformation", "n", "Number of cross-domain records",
             "Cumulative latency (ms, log scale)", True),
            ("e4_runs", "e4_verification", "verified", "Number of verified EHR records",
             "Verification latency (ms, log scale)", True),
            ("e6_runs", "e6_hospitals", "hospitals", "Number of Hospitals", "End-to-End Retrieval Latency (ms)",
             False)):
        rows = load(out, name)
        if rows:
            # the one-off first retrieval (which creates the linkage entries) stays in the summary table only
            series_plot(out, fname, rows, x, xl, yl, logy=logy, categorical=logy, style=scheme_style,
                        legend_loc="upper left", hide={("RBPRE-CALX", "first")})

    # ---------------------------------------------------------------- Exp 5
    rows = load(out, "e5_runs")
    if rows:
        series_plot(out, "e5_traceability", rows, "events", "Number of blockchain audit events",
                    "Blockchain overhead (ms, log scale)", key=("scheme",), style=scheme_style,
                    legend_loc="upper left")

    # ---------------------------------------------------------------- Exp 7
    rows = load(out, "e7_runs")
    if rows:
        for r in rows:
            r["ratio_pct"] = float(r["ratio"]) * 100

        def e7_style(k):
            c, mk, ls = E7_LINE.get(k[0], ("#000000", "x", "-"))
            return c, mk, ls, False, E7_NAME.get(k[0], k[0]), E7_ORDER.index(k[0]) if k[0] in E7_ORDER else 9

        series_plot(out, "e7_ablation_sweep", rows, "ratio_pct", r"Authorized fraction $|T_{\mathrm{auth}}|/N$",
                    "End-to-end retrieval latency\n(ms, log scale)", key=("variant",), style=e7_style, pct=True,
                    legend_loc="lower right")
        # Fig. 8 format at each measured ratio (the manuscript reports 10%)
        n_val = int(float(rows[0]["n"]))
        for ratio in sorted({r["ratio"] for r in rows}, key=float):
            by = defaultdict(list)
            for r in rows:
                if r["ratio"] == ratio:
                    by[r["variant"]].append(float(r["ms"]))
            names = [v for v in E7_ORDER if v in by]
            st = [stats(by[v]) for v in names]
            with plt.rc_context(BAR_RC):
                fig, ax = plt.subplots(figsize=(7.2, 4.4))
                bar_panel(ax, [E7_NAME[v] for v in names], st, [BLUE] + [GREY] * (len(names) - 1),
                          base=st[0][0] if names and names[0] == "full" else None)
                ax.set_xlabel("End-to-end retrieval latency (ms)")
                pct = f"{float(ratio) * 100:g}"
                save(fig, out, f"e7_ablation_{pct}pct",
                     [dict(variant=v, ratio=ratio, n=n_val, mean_ms=a, sd_ms=s, runs=c)
                      for v, (a, s, c) in zip(names, st)])
        wl = []
        for ratio in sorted({r["ratio"] for r in rows}, key=float):
            a = [float(r["ms"]) for r in rows if r["ratio"] == ratio and r["variant"] == E7_ORDER[3]]
            b = [float(r["ms"]) for r in rows if r["ratio"] == ratio and r["variant"] == E7_ORDER[4]]
            if len(a) > 1 and len(b) > 1:
                t, df, p = welch(a, b)
                wl.append(dict(ratio=ratio, mean_iii=stats(a)[0], mean_iv=stats(b)[0], t=t, df=df, p=p))
        if wl:
            with (out / "e7_welch.csv").open("w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(wl[0]))
                w.writeheader()
                w.writerows(wl)

    # ---------------------------------------------------------------- revocation
    rows = load(out, "erev_runs")
    if rows:
        # Fig. 8 bar format, one panel per patient size N. The live-session count S does not change the
        # event times, so each bar pools S (summary_erev_events.csv keeps every (event, N, S) point).
        rb = [r for r in rows if r["scheme"] == "RBPRE-CALX"]
        ns = sorted({int(r["n"]) for r in rb})
        names = list(dict.fromkeys(r["event"] for r in rb))
        summary = []
        with plt.rc_context(BAR_RC):
            fig, axes = plt.subplots(1, len(ns), figsize=(6.4 * len(ns), 0.75 * len(names) + 1.4), squeeze=False)
            for ax, n in zip(axes[0], ns):
                ev = defaultdict(list)
                for r in rb:
                    if int(r["n"]) == n:
                        ev[r["event"]].append(float(r["ms"]))
                st = [stats(ev[k]) if ev[k] else (0.0, 0.0, 0) for k in names]
                bar_panel(ax, [k[0].upper() + k[1:] for k in names], st, [BLUE] * len(names))
                ax.set_xlabel(f"Latency (ms), N = {n:,} records")
                for sn in sorted({int(r["sessions"]) for r in rb if int(r["n"]) == n}):
                    for k in names:
                        xs = [float(r["ms"]) for r in rb if int(r["n"]) == n and int(r["sessions"]) == sn
                              and r["event"] == k]
                        if xs:
                            a, sd, cnt = stats(xs)
                            summary.append(dict(event=k, n=n, sessions=sn, mean_ms=a, sd_ms=sd, runs=cnt))
            save(fig, out, "erev_events", summary)
        cmp_rows = [dict(r, variant="all") for r in rows if r["event"] in ("policy update", "policy update / revocation")]
        series_plot(out, "erev_policy_update", cmp_rows, "n", "Number of patient records",
                    "Policy update / revocation latency\n(ms, log scale)", key=("scheme",), style=scheme_style,
                    legend_loc="center right")


if __name__ == "__main__":
    main()

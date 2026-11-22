"""Move the rows of the given schemes out of a result table (they were measured
with the earlier baseline model), keeping every other row.

    python3 split_schemes.py <results/run dir> <label> <table> <scheme> [<scheme> ...]
"""
import csv
import sys
from pathlib import Path

out, label, table, schemes = Path(sys.argv[1]), sys.argv[2], sys.argv[3], set(sys.argv[4:])
(out / "superseded").mkdir(exist_ok=True)
p = out / f"{table}.csv"
with p.open(newline="") as f:
    rd = csv.DictReader(f)
    fields, rows = rd.fieldnames, list(rd)
keep = [r for r in rows if r["scheme"] not in schemes]
gone = [r for r in rows if r["scheme"] in schemes]
dst = out / "superseded" / f"{table}.{label}.csv"
if dst.exists():
    sys.exit(f"{dst} exists; already split?")
for path, part in ((dst, gone), (p, keep)):
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(part)
print(f"{table}: kept {len(keep)} rows, moved {len(gone)} rows of {sorted(schemes)} to superseded/{dst.name}")

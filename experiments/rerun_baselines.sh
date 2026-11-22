#!/usr/bin/env bash
# Re-measure the compared schemes after they were matched to their own papers
# (baselines/schemes.py, November 2026). Not run automatically.
#
#   RBPRE_RUN=quick-2026-11-21-i5 experiments/rerun_baselines.sh
#
# What changed, and therefore what is re-measured:
#   [25]  authentication (Table V of [25])          -> Exp 1
#   [27]  every operation (Table II of [27], MNT159) -> Exp 1, Exps 2-4, revocation
#   [31]  authentication (Sec. V-B of [31])          -> Exp 1
# Conventional PRE and RBPRE-CALX are unchanged. The earlier rows of the
# re-measured series are kept in results/$RBPRE_RUN/superseded/.
set -uo pipefail
cd "$(dirname "$0")/.."
: "${RBPRE_RUN:?set RBPRE_RUN}"
OUT=results/$RBPRE_RUN
PY="${PY:-$HOME/.venvs/rbpre-calx/bin/python}"
PLOT_PY="${PLOT_PY:-$HOME/flex-diam/venv/bin/python}"
SPLIT="python3 -I experiments/split_schemes.py"
# sizes (override for a smoke test, e.g. EXP1_ARGS="--k 1 10 --runs 2")
EXP1_ARGS="${EXP1_ARGS:---runs 10}"
EXP234_ARGS="${EXP234_ARGS:---n 1000 5000 10000 25000 50000 --runs 10 --runs-heavy 3}"
REV_ARGS="${REV_ARGS:---n 1000 10000 --sessions 1 10 50 --runs 5}"
REV_ONLY="${REV_ONLY:-[27]:1000 [27]:10000}"
TOPUP_ROUNDS="${TOPUP_ROUNDS:-2}"
log() { echo "$(date '+%F %T') $*" | tee -a "$OUT/progress.log"; }

$SPLIT "$OUT" baselines-before-paper-match e1b_runs "[25]" "[27]" "[31]"
$SPLIT "$OUT" baselines-before-paper-match e1g_runs "[25]" "[27]" "[31]"
for t in e2_runs e3_runs e4_runs; do $SPLIT "$OUT" baselines-before-paper-match $t "[27]"; done
$SPLIT "$OUT" baselines-before-paper-match erev_runs "[27]"

mkdir -p "$OUT/logs"
log "start baselines-exp1: Exp 1 (b) (RBPRE-CALX rows are added as extra runs)"
RBPRE_TOPUP=paper $PY -u -m experiments.exp1_authz --parts b $EXP1_ARGS > "$OUT/logs/baselines-exp1.log" 2>&1 \
  && log "done  baselines-exp1" || { log "FAIL  baselines-exp1"; exit 1; }

log "start baselines-exp234: [27] in Exps 2-4"
RBPRE_TOPUP=paper $PY -u -m experiments.exp234_retrieval $EXP234_ARGS --repo db \
    --only "e2:[27]" "e3:[27]" "e4:[27]" > "$OUT/logs/baselines-exp234.log" 2>&1 \
  && log "done  baselines-exp234" || { log "FAIL  baselines-exp234"; exit 1; }

log "start baselines-revocation: [27] policy update"
read -ra REV_TOK <<< "$REV_ONLY"   # tokens like [27]:1000, split without glob expansion
# shellcheck disable=SC2086
RBPRE_TOPUP=paper $PY -u -m experiments.exp_revocation $REV_ARGS --only "${REV_TOK[@]}" \
    > "$OUT/logs/baselines-revocation.log" 2>&1 \
  && log "done  baselines-revocation" || { log "FAIL  baselines-revocation"; exit 1; }

if [ "$TOPUP_ROUNDS" -gt 0 ]; then
  $PY -u -m experiments.topup --run "$RBPRE_RUN" --rounds "$TOPUP_ROUNDS" --first-round 5 --max-runs 30
else
  $PY -u -m experiments.topup --run "$RBPRE_RUN" --dry
fi
$PLOT_PY -u -m experiments.plot --run "$RBPRE_RUN" > "$OUT/logs/plot-baselines.log" 2>&1 \
  && log "done  plot after baseline re-measure" || log "FAIL  plot (see logs/plot-baselines.log)"

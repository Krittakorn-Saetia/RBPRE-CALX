#!/usr/bin/env bash
# Run the experiments in order into results/$RBPRE_RUN/, then the plots.
#
#   RBPRE_RUN=final-<machine> experiments/run_all.sh               # PROFILE=full
#   RBPRE_RUN=quick-<machine> PROFILE=quick experiments/run_all.sh
#
# full   every experiment with its default settings (30 runs per point)
# quick  the reviewer-requested set with fewer points and runs:
#        micro; Exp 1 (10 runs); Exps 2-4 at 1k/5k/10k/25k/50k records
#        (10 runs, heavy series 3); revocation at 1k/10k records with
#        1/10/50 sessions (5 runs); Exp 7 (10 runs)
#
# Resumable: a step that finished writes results/$RBPRE_RUN/done/<step> and is
# skipped on the next invocation. A failing step is logged and the script
# moves on. Each step's output is in results/$RBPRE_RUN/logs/<step>.log, and
# progress.log lists start, end and status per step.
#
# Prerequisites: infra/services.sh up, infra/fabric.sh up, the chaincode
# deployed, zk/rbzk and fabgw/fabgw built. PY selects the Python (default
# ~/.venvs/rbpre-calx); PLOT_PY one with matplotlib.
set -uo pipefail
cd "$(dirname "$0")/.."
: "${RBPRE_RUN:?set RBPRE_RUN, e.g. final-<machine>}"
export RBPRE_RUN
PROFILE="${PROFILE:-full}"
PY="${PY:-$HOME/.venvs/rbpre-calx/bin/python}"
PLOT_PY="${PLOT_PY:-$PY}"
OUT="results/$RBPRE_RUN"
mkdir -p "$OUT/logs" "$OUT/done"
log() { echo "$(date '+%F %T') $*" | tee -a "$OUT/progress.log"; }

run() {
  local name="$1"; shift
  if [ -f "$OUT/done/$name" ]; then log "skip  $name (done)"; return; fi
  log "start $name: $*"
  local t0=$SECONDS
  if "$@" > "$OUT/logs/$name.log" 2>&1; then
    touch "$OUT/done/$name"
    log "done  $name ($(( (SECONDS - t0) / 60 )) min)"
  else
    log "FAIL  $name after $(( (SECONDS - t0) / 60 )) min (see logs/$name.log)"
  fi
}

log "run $RBPRE_RUN ($PROFILE) on $(hostname)"
case "$PROFILE" in
  quick)
    run micro       "$PY" -u -m experiments.micro
    run exp1        "$PY" -u -m experiments.exp1_authz --runs 10
    run exp234      "$PY" -u -m experiments.exp234_retrieval --n 1000 5000 10000 25000 50000 --runs 10 --runs-heavy 3
    run revocation  "$PY" -u -m experiments.exp_revocation --n 1000 10000 --sessions 1 10 50 --runs 5
    run exp7        "$PY" -u -m experiments.exp7_ablation --runs 10
    ;;
  full)
    run micro       "$PY" -u -m experiments.micro
    run exp1        "$PY" -u -m experiments.exp1_authz
    run exp234      "$PY" -u -m experiments.exp234_retrieval
    run revocation  "$PY" -u -m experiments.exp_revocation
    run exp7        "$PY" -u -m experiments.exp7_ablation
    run exp6        "$PY" -u -m experiments.exp6_hospitals
    run exp5        "$PY" -u -m experiments.exp5_trace
    ;;
  *) log "unknown PROFILE $PROFILE"; exit 2 ;;
esac
rm -f "$OUT/done/plot"
run plot        "$PLOT_PY" -u -m experiments.plot --run "$RBPRE_RUN"
log "all steps attempted"

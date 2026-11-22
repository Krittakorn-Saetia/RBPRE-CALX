#!/usr/bin/env bash
# Fresh Quick run on this laptop: micro, Exp 1, Exps 2-4, revocation, Exp 7,
# then top-up of unstable points and the final plots. Resumable (re-run to continue).
cd "$(dirname "$0")"
export RBPRE_RUN="${RBPRE_RUN:-quick-2026-11-22-laptop}"
export PROFILE=quick
export PATH=/usr/local/go/bin:$PATH
PY=~/.venvs/rbpre-calx/bin/python
bash experiments/run_all.sh
if [ ! -f "results/$RBPRE_RUN/done/topup" ]; then
  $PY -u -m experiments.topup --run "$RBPRE_RUN" --rounds 2 > "results/$RBPRE_RUN/logs/topup.log" 2>&1 \
    && touch "results/$RBPRE_RUN/done/topup"
  rm -f "results/$RBPRE_RUN/done/plot"
  bash experiments/run_all.sh
fi
echo "ALL FINISHED $(date)" >> "results/$RBPRE_RUN/progress.log"

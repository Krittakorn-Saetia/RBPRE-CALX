#!/usr/bin/env bash
# Create the RBPRE-CALX Python environment (Ubuntu 22.04, native or WSL2).
#
#   RBPRE_VENV  where to create it        (default ~/.venvs/rbpre-calx)
#   CHARM_SRC   Charm-Crypto source tree  (default ~/flex-diam/charm; if it is
#               missing, charm-crypto-framework==0.63 is installed from PyPI)
#
# System packages needed once: build-essential python3-dev python3-venv
# libgmp-dev libssl-dev, and the PBC library in /usr/local/lib.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
VENV="${RBPRE_VENV:-$HOME/.venvs/rbpre-calx}"
CHARM_SRC="${CHARM_SRC:-$HOME/flex-diam/charm}"

python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$here/requirements.txt"
if [ -d "$CHARM_SRC" ]; then
  "$VENV/bin/python" -m pip install --quiet "$CHARM_SRC"
else
  "$VENV/bin/python" -m pip install --quiet "charm-crypto-framework==0.63"
fi
"$VENV/bin/python" -c 'import charm, cryptography, neo4j, redis, minio; print("environment ready")'
echo "python: $VENV/bin/python"

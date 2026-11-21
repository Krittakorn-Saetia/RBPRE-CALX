#!/usr/bin/env bash
# Start, stop or inspect the off-chain services (Neo4j, Redis, MinIO).
#
#   infra/services.sh up      generate infra/.env if missing, start, wait until ready
#   infra/services.sh down    stop (data volumes are kept)
#   infra/services.sh reset   stop and delete the data volumes
#   infra/services.sh status
#
# infra/.env holds random local passwords and is never committed.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
env_file="$here/.env"
dc() { docker compose -f "$here/docker-compose.yml" --env-file "$env_file" "$@"; }

gen_env() {
  [ -f "$env_file" ] && return
  pw() { head -c 18 /dev/urandom | base64 | tr -d '/+='; }
  umask 077
  {
    echo "NEO4J_PASSWORD=$(pw)"
    echo "REDIS_PASSWORD=$(pw)"
    echo "MINIO_PASSWORD=$(pw)"
  } > "$env_file"
  echo "wrote $env_file"
}

wait_ready() {
  for _ in $(seq 1 60); do
    if dc exec -T neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" "RETURN 1" >/dev/null 2>&1 \
      && dc exec -T redis redis-cli -a "$REDIS_PASSWORD" --no-auth-warning ping 2>/dev/null | grep -q PONG \
      && curl -sf http://127.0.0.1:9000/minio/health/ready >/dev/null; then
      echo "services ready"; return 0
    fi
    sleep 2
  done
  echo "services did not become ready" >&2; return 1
}

case "${1:-status}" in
  up)
    gen_env
    set -a; . "$env_file"; set +a
    dc up -d
    wait_ready
    ;;
  down)  dc down ;;
  reset) dc down -v ;;
  status) dc ps ;;
  *) echo "usage: $0 up|down|reset|status" >&2; exit 2 ;;
esac

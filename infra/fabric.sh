#!/usr/bin/env bash
# Bring up the Fabric test-network used by RBPRE-CALX and its channel "rbpre".
#
#   infra/fabric.sh up       start the test-network (restart stopped containers,
#                            or create it), then create channel rbpre if missing
#   infra/fabric.sh status
#
# The test-network lives in $FLEX_INFRA/fabric-samples (default ~/flex-diam),
# installed with Fabric 2.5.9 and BatchTimeout 1 s. Other channels on the same
# network (e.g. mychannel) are not touched.
set -euo pipefail
FLEX_INFRA="${FLEX_INFRA:-$HOME/flex-diam}"
TN="$FLEX_INFRA/fabric-samples/test-network"
CHANNEL="${RBPRE_CHANNEL:-rbpre}"
export PATH="$TN/../bin:$PATH" FABRIC_CFG_PATH="$TN/../config/"
NODES="orderer.example.com peer0.org1.example.com peer0.org2.example.com"

org1() {
  export CORE_PEER_TLS_ENABLED=true CORE_PEER_LOCALMSPID=Org1MSP CORE_PEER_ADDRESS=localhost:7051
  export CORE_PEER_TLS_ROOTCERT_FILE="$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
}

up() {
  if docker inspect $NODES >/dev/null 2>&1; then
    docker start $NODES >/dev/null
    echo "restarted existing test-network containers"
  else
    (cd "$TN" && ./network.sh up)
  fi
  org1
  for _ in $(seq 1 30); do peer channel list >/dev/null 2>&1 && break; sleep 1; done
  if peer channel getinfo -c "$CHANNEL" >/dev/null 2>&1; then
    echo "channel $CHANNEL exists"
  else
    (cd "$TN" && ./network.sh createChannel -c "$CHANNEL")
  fi
  peer channel getinfo -c "$CHANNEL"
}

case "${1:-status}" in
  up) up ;;
  status) docker ps --filter "name=example.com" --format '{{.Names}} {{.Status}}'; org1; peer channel list 2>/dev/null || true ;;
  *) echo "usage: $0 up|status" >&2; exit 2 ;;
esac

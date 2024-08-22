#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."
# shellcheck source=multinode-demo/common.sh
source multinode-demo/common.sh

rm -rf config/run/init-completed config/ledger config/snapshot-ledger

# Trigger eager build if needed; otherwise following steps cause odd timing error...
$solana_cli --version
$solana_ledger_tool --version
$agave_validator --version

SOLANA_RUN_SH_VALIDATOR_ARGS="--full-snapshot-interval-slots 200" \
  SOLANA_VALIDATOR_EXIT_TIMEOUT=30 \
  timeout 120 ./scripts/run.sh &

pid=$!

attempts=20
while [[ ! -f config/run/init-completed ]]; do
  sleep 1
  if ((--attempts == 0)); then
     echo "Error: validator failed to boot"
     exit 1
  else
    echo "Checking init"
  fi
done

snapshot_slot=50
latest_slot=0

# wait a bit longer than snapshot_slot
while [[ $latest_slot -le $((snapshot_slot + 1)) ]]; do
  sleep 1
  echo "Checking slot"
  latest_slot=$($solana_cli --url http://localhost:8899 slot --commitment processed)
done

$agave_validator --ledger config/ledger exit --force || true

wait $pid

$solana_ledger_tool create-snapshot --ledger config/ledger "$snapshot_slot" config/snapshot-ledger
cp config/ledger/genesis.tar.bz2 config/snapshot-ledger
$solana_ledger_tool copy --ledger config/ledger \
  --target-db config/snapshot-ledger --starting-slot "$snapshot_slot" --ending-slot "$latest_slot"
$solana_ledger_tool verify --abort-on-invalid-block \
  --ledger config/snapshot-ledger --block-verification-method blockstore-processor
$solana_ledger_tool verify --abort-on-invalid-block \
  --ledger config/snapshot-ledger --block-verification-method unified-scheduler

first_simulated_slot=$((latest_slot / 2))
echo "First simulated slot: ${first_simulated_slot}"
$solana_ledger_tool simulate-block-production --ledger config/ledger \
  --first-simulated-slot $first_simulated_slot
$solana_ledger_tool verify --abort-on-invalid-block \
  --ledger config/ledger --enable-hash-overrides

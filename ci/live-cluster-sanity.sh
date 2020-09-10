#!/usr/bin/env bash
set -e

# support testnet as well

cd "$(dirname "$0")/.."

source ci/_
source ci/rust-version.sh stable
source scripts/ulimit-n.sh

# shellcheck source=multinode-demo/common.sh
source multinode-demo/common.sh

rm -rf mainnet-beta-sanity
mkdir mainnet-beta-sanity

$solana_validator \
  --trusted-validator 7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2 \
  --trusted-validator GdnSyH3YtwcxFvQrVVJMm1JhTS4QVX7MFsX56uJLUfiZ \
  --trusted-validator DE1bawNcRJB9rVm3buyMVfr8mBEoyyu73NBovf2oXJsJ \
  --no-untrusted-rpc \
  --ledger mainnet-beta-sanity/ledger \
  --rpc-port 8899 \
  --dynamic-port-range 12001-12011 \
  --entrypoint mainnet-beta.solana.com:8001 \
  --expected-genesis-hash 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d \
  --expected-shred-version 64864 \
  --log mainnet-beta-sanity/validator.log \
  --init-complete-file mainnet-beta-sanity/init-completed \
  --enable-rpc-exit \
  --snapshot-interval-slots 0 &
pid=$!

tail -F mainnet-beta-sanity/validator.log > mainnet-beta-sanity/log-tail 2> /dev/null &
tail_pid=$!

attempts=100
while [[ ! -f mainnet-beta-sanity/init-completed ]]; do

  if find mainnet-beta-sanity/log-tail -not -empty | grep ^ > /dev/null; then
    echo
    echo "[progress]: validator is starting... (until timeout: $attempts)"
    echo "[new log]:"
    timeout 1 cat mainnet-beta-sanity/log-tail | tail -n 3 || true
    truncate --size 0 mainnet-beta-sanity/log-tail
  else
    echo "[progress]: validator is starting... (until timeout: $attempts)"
  fi

  attempts=$((attempts - 1))
  if [[ ((attempts == 0)) || ! -d "/proc/$pid" ]]; then
     set +e
     kill $pid
     wait $pid
     echo "Error: validator failed to boot"
     exit 1
  fi

  sleep 3
done

snapshot_slot=$(ls -t mainnet-beta-sanity/ledger/snapshot* | head -n 1 | grep -o 'snapshot-[0-9]*-' | grep -o '[0-9]*')

attempts=100
current_root=$snapshot_slot
goal_root=$((snapshot_slot + 100))
while [[ $current_root -le $goal_root ]]; do

  if find mainnet-beta-sanity/log-tail -not -empty | grep ^ > /dev/null; then
    echo
    echo "[progress]: validator is running ($current_root/$goal_root)... (until timeout: $attempts)"
    echo "[new log]:"
    timeout 1 cat mainnet-beta-sanity/log-tail | tail -n 3 || true
    truncate --size 0 mainnet-beta-sanity/log-tail
  else
    echo "[progress]: validator is running ($current_root/$goal_root)... (until timeout: $attempts)"
  fi

  attempts=$((attempts - 1))
  if [[ ((attempts == 0)) || ! -d "/proc/$pid" ]]; then
     set +e
     kill $pid $tail_pid
     wait $pid $tail_pid
     echo "Error: validator failed to boot"
     exit 1
  fi

  sleep 3
  current_root=$($solana_cli --url http://localhost:8899 slot --commitment root)
done

# currently doesn't work....
curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1, "method":"validatorExit"}' http://localhost:8899

(
  set +e
  # validatorExit doesn't work; so kill
  kill $pid $tail_pid
  wait $pid $tail_pid
) || true

# upload log as artifacts

#!/usr/bin/env bash
set -e

# support testnet as well

cd "$(dirname "$0")/.."

source ci/_
source ci/rust-version.sh stable
source ci/upload-ci-artifact.sh
source scripts/ulimit-n.sh

#_ cargo +"$rust_stable" build --release --bins ${V:+--verbose}
export CARGO_TOOLCHAIN=+"$rust_stable"
export NDEBUG=1

# shellcheck source=multinode-demo/common.sh
source multinode-demo/common.sh

instance_prefix="testnet-live-sanity-$RANDOM"
./net/gce.sh create -p "$instance_prefix" -n 0
abort() {
  if [[ -z $instance_deleted ]]; then
    _ ./net/gce.sh delete -p "$instance_prefix"
  fi
}
trap abort INT TERM EXIT

_ cargo +"$rust_stable" build --bins
./net/gce.sh info
instance_ip=$(./net/gce.sh info | grep bootstrap-validator | awk '{print $3}')

_ ./net/scp.sh ./target/release/solana-validator "$instance_ip":/tmp/

rm -rf mainnet-beta-sanity
mkdir mainnet-beta-sanity

echo 500000 | ./net/ssh.sh "$instance_ip" sudo tee -a /proc/sys/vm/max_map_count

(./net/ssh.sh "$instance_ip" -Llocalhost:8989:localhost:8989 /tmp/solana-validator \
  --trusted-validator 7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2 \
  --trusted-validator GdnSyH3YtwcxFvQrVVJMm1JhTS4QVX7MFsX56uJLUfiZ \
  --trusted-validator DE1bawNcRJB9rVm3buyMVfr8mBEoyyu73NBovf2oXJsJ \
  --no-untrusted-rpc \
  --ledger mainnet-beta-sanity/ledger \
  --entrypoint mainnet-beta.solana.com:8001 \
  --expected-genesis-hash 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d \
  --expected-shred-version 64864 \
  --log - \
  --init-complete-file mainnet-beta-sanity/init-completed \
  --enable-rpc-exit \
  --private-rpc \
  --rpc-bind-address localhost \
  --snapshot-interval-slots 0) >> mainnet-beta-sanity/validator.log 2>&1 &
pid=$!


tail -F mainnet-beta-sanity/validator.log > mainnet-beta-sanity/log-tail 2> /dev/null &
tail_pid=$!

exit_after_upload() {
  upload-ci-artifact mainnet-beta-sanity/validator.log
  exit $1
}

echo "--- Starting validator"

attempts=100
while ! ./net/ssh.sh "$instance_ip" test -f mainnet-beta-sanity/init-completed; do

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
  if [[ (($attempts == 0)) || ! -d "/proc/$pid" ]]; then
     set +e
     kill $pid
     wait $pid
     echo "Error: validator failed to boot"
     exit_after_upload 1
  fi

  sleep 3
done

snapshot_slot=$(./net/ssh.sh "$instance_ip" ls -t mainnet-beta-sanity/ledger/snapshot* | head -n 1 | grep -o 'snapshot-[0-9]*-' | grep -o '[0-9]*')

echo "--- Monitoring validator"

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
  if [[ (($attempts == 0)) || ! -d "/proc/$pid" ]]; then
     set +e
     kill $pid $tail_pid
     wait $pid $tail_pid
     echo "Error: validator failed to boot"
     exit_after_upload 1
  fi

  sleep 3
  current_root=$(./target/release/solana --url http://localhost:8899 slot --commitment root)
done

# currently doesn't work....
curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1, "method":"validatorExit"}' http://localhost:8899

(
  set +e
  # validatorExit doesn't work; so kill
  kill $pid $tail_pid
  wait $pid $tail_pid
) || true

exit_after_upload 0
./net/gce.sh delete -p "$instance_prefix" && instance_deleted=yes

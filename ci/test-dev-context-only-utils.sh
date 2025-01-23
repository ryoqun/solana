#!/usr/bin/env bash

set -eo pipefail

check_dcou() {
  scripts/check-dev-context-only-utils.sh check-all-targets "$@"
  scripts/check-dev-context-only-utils.sh check-bins-and-lib "$@"
}

unset SCCACHE_GCS_KEY_PATH SCCACHE_GCS_BUCKET SCCACHE_GCS_RW_MODE SCCACHE_GCS_KEY_PREFIX

source ./ci/_

_ df -h ~/.cache || true
_ df -h ~/.cache/sccache || true
_ du -sh ~/.cache/sccache || true

shard=$1
shift
_ echo update sccache and install mold
# apt-get install mold clang
(unset RUSTC_WRAPPER; cargo install --force --git https://github.com/ryoqun/cargo-hack.git --branch interleaved-partition cargo-hack)
#(unset RUSTC_WRAPPER; cargo install --force sccache)

_ echo before:
ls -ltr --full-time ./target || true
du -shc ./target/* || true
sccache --show-stats
case "$shard" in
  1-of-4)
    check_dcou --partition 1/3
    ;;
  2-of-4)
    check_dcou --partition 2/3
    ;;
  3-of-4)
    check_dcou --partition 3/3
    ;;
  4-of-4)
    check_dcou
    ;;
  *)
    echo "$0: unrecognized shard: $shard";
    exit 1
    ;;
esac

_ echo end:
ls -ltr --full-time ./target || true
du -shc ./target/* || true
sccache --stop-server
echo "pub type AAA = u32;" >> "sdk/src/lib.rs"

_ echo before2:
rm -rf ./target
sccache --show-stats
case "$shard" in
  1-of-4)
    check_dcou --partition 1/3
    ;;
  2-of-4)
    check_dcou --partition 2/3
    ;;
  3-of-4)
    check_dcou --partition 3/3
    ;;
  4-of-4)
    check_dcou
    ;;
  *)
    echo "$0: unrecognized shard: $shard";
    exit 1
    ;;
esac

_ echo end2:
ls -ltr --full-time ./target || true
du -shc ./target/* || true
sccache --stop-server

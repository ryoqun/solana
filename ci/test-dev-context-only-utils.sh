#!/usr/bin/env bash

set -eo pipefail

check_dcou() {
  scripts/check-dev-context-only-utils.sh check-all-targets "$@"
  scripts/check-dev-context-only-utils.sh check-bins-and-lib "$@"
}

unset SCCACHE_GCS_KEY_PATH SCCACHE_GCS_BUCKET SCCACHE_GCS_RW_MODE SCCACHE_GCS_KEY_PREFIX

source ./ci/_

shard=$1
shift
_ echo update sccache
cargo install sccache

_ echo before:
ls -ltr --full-time ./target || true
du -shc ./target/* || true
sccache --show-stats
case "$shard" in
  1-of-4)
    check_dcou --partition 1/9
    check_dcou --partition 2/9
    check_dcou --partition 3/9
    check_dcou --partition 4/9
    check_dcou --partition 5/9
    ;;
  2-of-4)
    check_dcou --partition 6/9
    check_dcou --partition 7/9
    ;;
  3-of-4)
    check_dcou --partition 8/9
    ;;
  4-of-4)
    check_dcou --partition 9/9
    ;;
  *)
    echo "$0: unrecognized shard: $shard";
    exit 1
    ;;
esac

_ echo end:
ls -ltr --full-time ./target || true
du -shc ./target/* || true
sccache --show-stats
sccache --stop-server

_ echo before2:
rm -rf ./target
sccache --show-stats
case "$shard" in
  1-of-4)
    check_dcou --partition 1/9
    check_dcou --partition 2/9
    check_dcou --partition 3/9
    check_dcou --partition 4/9
    check_dcou --partition 5/9
    ;;
  2-of-4)
    check_dcou --partition 6/9
    check_dcou --partition 7/9
    ;;
  3-of-4)
    check_dcou --partition 8/9
    ;;
  4-of-4)
    check_dcou --partition 9/9
    ;;
  *)
    echo "$0: unrecognized shard: $shard";
    exit 1
    ;;
esac

_ echo end2:
ls -ltr --full-time ./target || true
du -shc ./target/* || true
sccache --show-stats
sccache --stop-server

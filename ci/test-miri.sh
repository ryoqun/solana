#!/usr/bin/env bash

set -eo pipefail

source ci/rust-version.sh nightly

rustup component add miri --toolchain "$rust_nightly"

# miri is very slow; so only run very few of selective tests!
cargo "+${rust_nightly}" miri test -p solana-program -- hash:: account_info::


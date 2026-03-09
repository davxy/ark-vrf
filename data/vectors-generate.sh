#!/usr/bin/env bash

cd "$(dirname "$0")"
mkdir -p vectors

cargo test \
  --lib \
  --release \
  --features full,test-vectors,blake3,shake128 \
  -- \
  --nocapture \
  --ignored

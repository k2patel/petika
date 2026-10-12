#!/bin/sh
set -eu
# Install once: rustup target add wasm32-unknown-unknown
# cargo install wasm-bindgen-cli --version 0.2.114 --locked
cargo build --locked --release -p petika-web --target wasm32-unknown-unknown
wasm-bindgen --target web --no-typescript --out-dir clients/web/wasm --out-name petika_web target/wasm32-unknown-unknown/release/petika_web.wasm

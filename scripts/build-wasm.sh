#!/usr/bin/env sh
# Compila il core in WebAssembly e genera i binding JS/TS per la PWA.
# Richiede: target wasm32-unknown-unknown (rust-toolchain.toml) e
# wasm-bindgen-cli alla stessa versione del crate wasm-bindgen (vedi crates/wasm/Cargo.toml).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/apps/web/src/wasm"
expected=$(sed -n 's/^wasm-bindgen = "=\(.*\)"$/\1/p' "$root/crates/wasm/Cargo.toml")
actual=$(wasm-bindgen --version | cut -d' ' -f2)
if [ "$expected" != "$actual" ]; then
  echo "wasm-bindgen-cli $actual installato, richiesto $expected:" >&2
  echo "  cargo install --locked wasm-bindgen-cli --version $expected" >&2
  exit 1
fi

cargo build --manifest-path "$root/Cargo.toml" -p authenticator-wasm \
  --target wasm32-unknown-unknown --release --locked
wasm-bindgen --target web --out-dir "$out" \
  "$root/target/wasm32-unknown-unknown/release/authenticator_wasm.wasm"
echo "WebAssembly generato in $out ($(wc -c < "$out/authenticator_wasm_bg.wasm") byte)"

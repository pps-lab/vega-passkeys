#!/bin/bash
# Run Script phase of the PopVega target in ios/Verena.xcodeproj. Builds the prover static
# library for the platform Xcode is building and generates its Swift bindings into
#   $BUILT_PRODUCTS_DIR/PopVegaFFI/
#     libpop_vega_ffi.a             linked by the app targets (-lpop_vega_ffi)
#     include/pop_vega_ffiFFI.h     C interface, imported by the bindings as pop_vega_ffiFFI
#     include/module.modulemap
#     pop_vega_ffi.swift            UniFFI-generated Swift API, compiled into the PopVega module
# Always runs; cargo decides what is stale. Outputs are only replaced when their content
# changes, so a no-op cargo build doesn't recompile or relink the app.
#
# Needs rustup with: rustup target add aarch64-apple-ios aarch64-apple-ios-sim
set -euo pipefail
cd "$(dirname "$0")/.."            # vega/

case "${PLATFORM_NAME:?run from Xcode}" in
  iphoneos)        TARGET=aarch64-apple-ios ;;
  iphonesimulator) TARGET=aarch64-apple-ios-sim ;;
  *) echo "error: PopVega: unsupported platform $PLATFORM_NAME"; exit 1 ;;
esac
OUT="${BUILT_PRODUCTS_DIR:?}/PopVegaFFI"

# Xcode exports SDKROOT, deployment targets and toolchain variables that point at the iOS SDK
# and break cargo's host builds (build scripts, uniffi-bindgen). Run cargo in a clean
# environment, keeping only what rustup/cargo and xcrun need.
PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
CLEAN_ENV=(env -i "HOME=$HOME" "PATH=$PATH" "IPHONEOS_DEPLOYMENT_TARGET=16.0")
[ -n "${DEVELOPER_DIR:-}" ] && CLEAN_ENV+=("DEVELOPER_DIR=$DEVELOPER_DIR")
while IFS='=' read -r name value; do
  CLEAN_ENV+=("$name=$value")
done < <(env | grep -E '^(CARGO|RUSTUP|RUSTC|SCCACHE)_[A-Z_]*=' || true)
if ! command -v cargo >/dev/null; then
  echo "error: PopVega: cargo not found. Install Rust (https://rustup.rs), then: rustup target add aarch64-apple-ios aarch64-apple-ios-sim"
  exit 1
fi
cargo() { "${CLEAN_ENV[@]}" cargo "$@"; }

"${CLEAN_ENV[@]}" ./scripts/fetch-vega-prover.sh

# Release even for Debug app builds: an unoptimized prover is unusably slow.
cargo build --release -p pop-vega-ffi --lib --target "$TARGET"
# Host tool only; it reads the interface metadata from the iOS static library.
cargo build -p pop-vega-ffi --features cli --bin uniffi-bindgen
TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
LIB="$TARGET_DIR/$TARGET/release/libpop_vega_ffi.a"

GEN="$TARGET_DIR/xcode-bindings/$TARGET"
rm -rf "$GEN" && mkdir -p "$GEN"
"$TARGET_DIR/debug/uniffi-bindgen" generate --library "$LIB" --language swift --out-dir "$GEN" >/dev/null

install_if_changed() {             # src dst
  if ! cmp -s "$1" "$2"; then
    mkdir -p "$(dirname "$2")"
    cp "$1" "$2"
  fi
}
install_if_changed "$LIB"                             "$OUT/libpop_vega_ffi.a"
install_if_changed "$GEN/pop_vega_ffiFFI.h"           "$OUT/include/pop_vega_ffiFFI.h"
install_if_changed "$GEN/pop_vega_ffiFFI.modulemap"   "$OUT/include/module.modulemap"
install_if_changed "$GEN/pop_vega_ffi.swift"          "$OUT/pop_vega_ffi.swift"

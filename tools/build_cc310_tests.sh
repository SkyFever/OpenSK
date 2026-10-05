#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build-only common cross-check/benchmark and existing Nordic vector applets.
set -euo pipefail
cd "$(dirname "$0")/.."
./tools/apply_cc310_patch.sh
python3 tools/setup_cc310.py
OUT="$PWD/build/hw-crypto"
mkdir -p "$OUT"
cd third_party/wasefire
SOFTWARE="software-crypto-aes256-cbc,software-crypto-hmac-sha256,software-crypto-p256-ecdh,software-crypto-p256-ecdsa,software-crypto-ed25519"
NORDIC="hardware-crypto-p256,hardware-crypto-symmetric,hardware-crypto-ed25519"
build_image() {
  local applet="$1" name="$2" runner_features="$3" applet_features="$4"
  cargo xtask --native applet rust "$applet" --features="$applet_features" --opt-level=z \
    runner nordic --board=makerdiary --opt-level=z --features="$runner_features" \
    flash --artifacts </dev/null
  cp target/wasefire/platform.hex "$OUT/$name.hex"
  cp target/thumbv7em-none-eabi/release/runner-nordic "$OUT/$name.elf"
  python3 ../../tools/makerdiary_artifacts.py patch-hex "$OUT/$name.hex"
  ./scripts/wrapper.sh uf2conv.py --family=0xADA52840 --convert \
    --output="$OUT/$name.uf2" "$OUT/$name.hex"
  python3 ../../tools/makerdiary_artifacts.py verify-uf2 "$OUT/$name.uf2"
}
# Dual-slot flash/bootloader packaging cannot fit both crypto references plus
# Ed25519 after adding mandatory software AES-256. Keep Ed25519 in its own
# vector image; the shared benchmark covers P-256, CBC and SHA/HMAC.
build_image crypto_compare software-crypto-compare "${SOFTWARE%,software-crypto-ed25519}" ""
build_image crypto_compare nordic-crypto-compare "${NORDIC%,hardware-crypto-ed25519}" nordic
for APPLET in ecdsa_test ecdh_test cbc_test hash_test ed25519_test; do
  build_image "$APPLET" "nordic-$APPLET" "$NORDIC" ""
done
printf 'Cross-check, benchmark and vector images built; no device was accessed.\n'
printf 'RTT tests and timings have NOT RUN on hardware.\n'

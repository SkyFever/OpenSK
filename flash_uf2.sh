#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Build-only OpenSK -> complete Wasefire Makerdiary flash artifact -> UF2.
#
# IMPORTANT:
#   This intentionally invokes Wasefire's `flash --artifacts` mode.
#   Despite the subcommand name, --artifacts makes Wasefire produce the
#   canonical flash image WITHOUT accessing or flashing a physical device.
#
#   Do NOT replace this with a bare `runner nordic` build and objcopy the
#   runner-nordic ELF. The runner ELF is only a platform side and is not the
#   complete Makerdiary bootstrap image expected by the UF2 bootloader.

set -euo pipefail

FEATURES="ctap1,config-command"
OUTPUT=""
TARGET=""
CRYPTO="software"
CRYPTO_TRACE=false

usage() {
  cat <<USAGE
Usage: $0 [options] nrf52840_mdk

Options:
  --features=<features>  Comma-separated OpenSK applet features
                         (default: $FEATURES)
  --crypto=<backend>    Crypto backend: software (default) or cc310
  --crypto-trace        Show active CC310 operation on the Makerdiary RGB LED
  --output=<file>        Output UF2 path
                         (default: build/opensk-nrf52840_mdk.uf2)
  -h, --help             Show this help

This script is build-only. It does NOT access or flash a USB device.
It asks Wasefire to generate its canonical flash artifact and then converts
that artifact to UF2 locally.
USAGE
  exit "${1:-1}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --features=*)
      FEATURES="${1#*=}"
      shift
      ;;
    --crypto=*)
      CRYPTO="${1#*=}"
      shift
      ;;
    --crypto-trace)
      CRYPTO_TRACE=true
      shift
      ;;
    --output=*)
      OUTPUT="${1#*=}"
      shift
      ;;
    -h|--help)
      usage 0
      ;;
    *)
      if [[ -z "$TARGET" ]]; then
        TARGET="$1"
        shift
      else
        echo "Error: Unknown argument: $1" >&2
        usage 1
      fi
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Error: Target is required." >&2
  usage 1
fi

if [[ "$TARGET" != "nrf52840_mdk" ]]; then
  echo "Error: This UF2 builder is intentionally limited to nrf52840_mdk." >&2
  echo "       Requested target: $TARGET" >&2
  exit 1
fi

case "$CRYPTO" in
  software|cc310) ;;
  *) echo "Error: Unknown crypto backend: $CRYPTO" >&2; exit 1 ;;
esac

if [[ "$CRYPTO_TRACE" == true && "$CRYPTO" != cc310 ]]; then
  echo "Error: --crypto-trace requires --crypto=cc310." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

WASEFIRE_DIR="third_party/wasefire"
if [[ ! -d "$WASEFIRE_DIR" ]] || [[ -z "$(ls -A "$WASEFIRE_DIR" 2>/dev/null)" ]]; then
  echo "$WASEFIRE_DIR is empty or does not exist. Run './setup.sh' first." >&2
  exit 1
fi

# The committed source patch keeps upstream submodule clones reproducible.
./tools/apply_cc310_patch.sh

if [[ -z "$OUTPUT" ]]; then
  if [[ "$CRYPTO" == cc310 ]]; then
    if [[ "$CRYPTO_TRACE" == true ]]; then
      OUTPUT="$SCRIPT_DIR/build/opensk-nrf52840_mdk-cc310-trace.uf2"
    else
      OUTPUT="$SCRIPT_DIR/build/opensk-nrf52840_mdk-cc310.uf2"
    fi
  else
    OUTPUT="$SCRIPT_DIR/build/opensk-nrf52840_mdk.uf2"
  fi
elif [[ "$OUTPUT" != /* ]]; then
  OUTPUT="$SCRIPT_DIR/$OUTPUT"
fi
mkdir -p "$(dirname "$OUTPUT")"

HEX_OUTPUT="${OUTPUT%.uf2}.hex"
if [[ "$HEX_OUTPUT" == "$OUTPUT" ]]; then
  HEX_OUTPUT="$OUTPUT.hex"
fi

# OpenSK's Makerdiary target requires led-1 in addition to the requested applet
# features, matching the upstream OpenSK flash.sh behavior.
MDK_FEATURES="$FEATURES"
if [[ ! ",$MDK_FEATURES," =~ ,led-1, ]]; then
  MDK_FEATURES="${MDK_FEATURES:+$MDK_FEATURES,}led-1"
fi

if [[ "$CRYPTO" == cc310 ]]; then
  python3 tools/setup_cc310.py
  RUNNER_CRYPTO_FEATURES="hardware-crypto-p256,hardware-crypto-symmetric,hardware-crypto-rng,hardware-crypto-aes128-ccm,cc310-primitives"
else
  RUNNER_CRYPTO_FEATURES="software-crypto-aes256-cbc,software-crypto-hmac-sha256"
  RUNNER_CRYPTO_FEATURES+=",software-crypto-p256-ecdh,software-crypto-p256-ecdsa"
fi
if [[ "$CRYPTO_TRACE" == true ]]; then
  RUNNER_CRYPTO_FEATURES+=",cc310-trace"
fi
if [[ ",$MDK_FEATURES," == *,ed25519,* ]]; then
  if [[ "$CRYPTO" == cc310 ]]; then
    RUNNER_CRYPTO_FEATURES+=",hardware-crypto-ed25519"
  else
    RUNNER_CRYPTO_FEATURES+=",software-crypto-ed25519"
  fi
fi

cd "$WASEFIRE_DIR"

echo "Building target: nrf52840_mdk (Makerdiary)"
echo "OpenSK features: $MDK_FEATURES"
echo "Crypto backend: $CRYPTO"
if [[ "$CRYPTO" == cc310 ]]; then
  echo "CC310: P-256 / SHA-256 / HMAC-SHA256 / RNG / AES-128-CCM"
  if [[ ",$MDK_FEATURES," == *,ed25519,* ]]; then
    echo "CC310: Ed25519"
  fi
  echo "AES-256-CBC: software"
fi
echo "CC310 LED diagnostics: $CRYPTO_TRACE"
echo "Mode: canonical flash artifact only; NO device access / NO flash"
echo

# This is the important part.
#
# Wasefire's `flash --artifacts` path does all of the packaging performed by a
# real flash operation, including:
#   1. compiling runner-nordic,
#   2. compiling the Wasefire Nordic bootloader,
#   3. bundling the native OpenSK runner into the bootloader's .runner section,
#   4. emitting target/wasefire/platform.hex,
# while stopping before the actual hardware flashing step.
cargo xtask --release --native applet rust ../.. --opt-level=z --features="$MDK_FEATURES" \
  runner nordic --board=makerdiary --opt-level=z --features=usb-ctap \
  --features="$RUNNER_CRYPTO_FEATURES" \
  flash --artifacts </dev/null

PLATFORM_HEX="$PWD/target/wasefire/platform.hex"
if [[ ! -s "$PLATFORM_HEX" ]]; then
  echo "Error: Wasefire did not produce the expected flash artifact:" >&2
  echo "       $PLATFORM_HEX" >&2
  echo >&2
  echo "Check whether this checkout supports 'flash --artifacts':" >&2
  echo "  cd '$WASEFIRE_DIR' && cargo xtask help runner flash" >&2
  exit 1
fi

cp "$PLATFORM_HEX" "$HEX_OUTPUT"
python3 "$SCRIPT_DIR/tools/makerdiary_artifacts.py" patch-hex "$HEX_OUTPUT"

# Inspect the canonical HEX before UF2 conversion. This also catches the exact
# mistake made by the previous script: feeding the raw runner ELF (which began
# at 0x00008000) to objcopy instead of using the packaged platform artifact.
python3 - "$HEX_OUTPUT" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
base = 0
lo = None
hi = None
bytes_total = 0

for raw in path.read_text(encoding="ascii").splitlines():
    if not raw.startswith(":") or len(raw) < 11:
        continue
    count = int(raw[1:3], 16)
    addr = int(raw[3:7], 16)
    typ = int(raw[7:9], 16)
    data = bytes.fromhex(raw[9:9 + count * 2])
    if typ == 0x00:
        start = base + addr
        end = start + count
        lo = start if lo is None else min(lo, start)
        hi = end if hi is None else max(hi, end)
        bytes_total += count
    elif typ == 0x02 and count == 2:
        base = int.from_bytes(data, "big") << 4
    elif typ == 0x04 and count == 2:
        base = int.from_bytes(data, "big") << 16

if lo is None:
    raise SystemExit("Error: generated platform.hex contains no data records")

print(f"Canonical HEX data range: 0x{lo:08x} .. 0x{hi - 1:08x}")
print(f"Canonical HEX payload: {bytes_total} bytes")

# A complete Makerdiary bootstrap should contain data below the raw runner-side
# address used by the current dual-sided Nordic layout. Do not silently emit the
# same broken artifact as the old script.
if lo >= 0x8000:
    raise SystemExit(
        "Error: platform.hex unexpectedly starts at/above 0x00008000; "
        "refusing to emit a runner-only UF2"
    )
PY

# Use the exact uf2conv.py family/tooling path Wasefire itself uses. `-c` is
# critical: it means convert only, so uf2conv will NOT scan for or write to a
# mounted UF2BOOT device. wrapper.sh downloads Microsoft's official converter
# into Wasefire's local .root when it is not already installed.
./scripts/wrapper.sh uf2conv.py \
  --family=0xADA52840 \
  --convert \
  --output "$OUTPUT" \
  "$HEX_OUTPUT"

if [[ ! -s "$OUTPUT" ]]; then
  echo "Error: UF2 conversion did not create: $OUTPUT" >&2
  exit 1
fi

# Read back the UF2 and report what will actually be written. This is only a
# structural sanity check; it never touches USB.
python3 - "$OUTPUT" <<'PY'
from pathlib import Path
import struct
import sys

path = Path(sys.argv[1])
data = path.read_bytes()

MAGIC0 = 0x0A324655
MAGIC1 = 0x9E5D5157
MAGIC_END = 0x0AB16F30
FAMILY_FLAG = 0x00002000
EXPECTED_FAMILY = 0xADA52840

if len(data) == 0 or len(data) % 512:
    raise SystemExit("Error: invalid UF2 size")

lo = None
hi = None
families = set()
blocks = len(data) // 512

for i in range(blocks):
    block = data[i * 512:(i + 1) * 512]
    m0, m1, flags, addr, size, block_no, block_count, family = struct.unpack(
        "<IIIIIIII", block[:32]
    )
    end_magic, = struct.unpack("<I", block[508:512])
    if (m0, m1, end_magic) != (MAGIC0, MAGIC1, MAGIC_END):
        raise SystemExit(f"Error: invalid UF2 magic in block {i}")
    if size > 476:
        raise SystemExit(f"Error: invalid UF2 payload size in block {i}: {size}")
    if block_no != i or block_count != blocks:
        raise SystemExit(f"Error: inconsistent UF2 block numbering at block {i}")
    lo = addr if lo is None else min(lo, addr)
    hi = addr + size if hi is None else max(hi, addr + size)
    if flags & FAMILY_FLAG:
        families.add(family)

print(f"UF2 blocks: {blocks}")
print(f"UF2 address range: 0x{lo:08x} .. 0x{hi - 1:08x}")
if families:
    print("UF2 family ID(s): " + ", ".join(f"0x{x:08x}" for x in sorted(families)))
if families and families != {EXPECTED_FAMILY}:
    raise SystemExit(
        "Error: unexpected UF2 family ID(s): "
        + ", ".join(f"0x{x:08x}" for x in sorted(families))
    )
print(f"UF2 size: {len(data)} bytes")
print("UF2 verification: OK")
PY

python3 "$SCRIPT_DIR/tools/makerdiary_artifacts.py" verify-uf2 "$OUTPUT"

echo
printf 'Build complete. No device was accessed or flashed.\n'
printf 'Canonical HEX: %s\n' "$HEX_OUTPUT"
printf 'UF2:           %s\n' "$OUTPUT"
printf 'SHA-256:       '
sha256sum "$OUTPUT" | awk '{print $1}'

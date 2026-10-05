# Makerdiary CC310 backend

The `--crypto=cc310` build uses Nordic CC310 for P-256, SHA-256 and
HMAC-SHA256. AES-256-CBC keeps the existing software backend because CC310
supports only 128-bit AES keys. Optional Ed25519 uses the CC310 driver.

| Operation | `software` | `cc310` |
| --- | --- | --- |
| P-256 keygen, public key, ECDSA, ECDH | RustCrypto | CC310 |
| SHA-256, HMAC-SHA256 | RustCrypto | CC310 |
| AES-256-CBC | RustCrypto | RustCrypto |
| Optional Ed25519 | RustCrypto | CC310 |
| General RNG | nRF RNG peripheral | CC310 TRNG-seeded AES CTR-DRBG |

This integrates the operations used by OpenSK; it does not expose every
CryptoCell algorithm. The CC310 adapter also exposes direct TRNG entropy.
PSA key-generation requests share the guarded CTR-DRBG without recursive locking.

## Build

Run `./setup.sh` to initialize the upstream dependencies. The CC310 C shim also
requires `clang-18`, `llvm-ar` and Python. Builds use the pinned Rust toolchain.

```sh
./flash_uf2.sh --crypto=software nrf52840_mdk
./flash_uf2.sh --crypto=cc310 --output=build/hw-crypto/opensk-nordic.uf2 nrf52840_mdk
# Optional Ed25519:
./flash_uf2.sh --crypto=cc310 --features=ctap1,config-command,ed25519 nrf52840_mdk
```

These commands generate HEX/UF2 files without accessing a device. Flash the
chosen UF2 using the board's existing UF2 bootloader.

The builders automatically apply `tools/patches/wasefire-cc310.patch` to the
pinned upstream Wasefire revision `6d8f4fc9714004af9d86b4218da0ce6d52db84f4`.
The submodule reference stays upstream; its local modifications are represented
by this committed patch. Manual replay is available through
`./tools/apply_cc310_patch.sh`; it is idempotent and does not reset local files.

`tools/setup_cc310.py` downloads hash-pinned dependencies from
`tools/cc310-deps.json` into the ignored `third_party/wasefire/.root/cc310`
cache. Run `python3 tools/setup_cc310.py --check` to check an existing cache.
The adapter can override its compiler/archive/cache paths with `CC310_CC`,
`CC310_AR` and `OPENSK_CC310_DIR`.

## Dependencies and packaging

- nrfxlib v2.9.2: `1143aee1e0521b5309e891b44a0a8048f83074d2`.
- Mbed TLS v3.6.2-ncs2-2: `98603a8c91660beac00e0ee1d76198fb7c4ed29b`.
- CC310 PSA/core/platform v0.9.19: Cortex-M4 soft-float, no-interrupts.

Nordic components retain their Nordic 5-Clause licenses and chip-use
restrictions. Mbed TLS headers retain their Apache-2.0 notices. SDK archives,
private key material and build output are not included in the source patch.

The builder packages Wasefire's complete Makerdiary flash artifact. It clears
S132 metadata at `0x3000..0x300f`, verifies the UF2 family and bootstrap, and
rejects images that touch the credential store, recovery bootloader or UICR.

## Optional diagnostics

```sh
./flash_uf2.sh --crypto=cc310 --crypto-trace nrf52840_mdk
```

Static colors identify the active hardware call: green HMAC, yellow keygen,
blue public-key processing, magenta ECDSA, cyan ECDH and white SHA. Successful
calls clear the color; the first returned driver error keeps it across cleanup.
Normal user-presence blinking remains separate.

`tools/crypto_hil.py` supports explicitly selected device info, credential
creation/assertion and negative checks. It prints keepalive transitions and
never resets the device or changes its PIN. Its cancellation timer is
best-effort; a stalled blocking HID read may require Ctrl+C.

`tools/build_cc310_tests.sh` optionally builds comparison/benchmark and vector
images. The common images omit Ed25519 to fit the existing dual-slot layout;
Ed25519 has a separate vector image. Benchmark timings require hardware execution.

Registration, assertion, ES256 verification, wrong-RP/tampered-ID rejection and
Token2 registration/login passed with the corrected firmware on the user's
board. Valid attestation still requires separately provisioned AAGUID/certificate
material; enabling batch attestation alone does not provision it.
\nNew CC310 Ed25519 and general RNG paths have passed host adapter tests and\nARM builds. Their physical-device execution remains to be verified.\n
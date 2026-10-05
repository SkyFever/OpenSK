# Makerdiary CC310 backend

The `--crypto=cc310` build uses Nordic CC310 for P-256, SHA-256 and
HMAC-SHA256, general RNG and the AES-128-CCM board API. AES-256-CBC keeps
the existing software backend because CC310 supports only 128-bit AES keys. Optional Ed25519 uses the CC310 driver.

| Operation | `software` | `cc310` |
| --- | --- | --- |
| P-256 keygen, public key, ECDSA, ECDH | RustCrypto | CC310 |
| SHA-256, HMAC-SHA256 | RustCrypto | CC310 |
| AES-128-CCM board API | nRF CCM peripheral or RustCrypto | CC310 |
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
# Enable Ed25519 credentials as well:
./flash_uf2.sh --crypto=cc310 --features=ctap1,config-command,ed25519 \
  --output=build/hw-crypto/opensk-nordic.uf2 nrf52840_mdk
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
never resets the device or changes its PIN. Select `--algorithm ed25519`
when creating a test credential to exercise CC310 Ed25519; later assertions
use the algorithm in the saved record. The default creation algorithm is ES256.
Its cancellation timer is best-effort; a stalled blocking HID read may require Ctrl+C.

`tools/build_cc310_tests.sh` optionally builds comparison/benchmark and vector
images. The common images omit Ed25519 to fit the existing dual-slot layout;
Ed25519 has a separate vector image. Benchmark timings require hardware execution.

Registration, assertion, ES256 verification, wrong-RP/tampered-ID rejection and
Token2 registration/login passed with the corrected firmware on the user's
board. Valid attestation still requires separately provisioned AAGUID/certificate
material; enabling batch attestation alone does not provision it.

New CC310 Ed25519 and general RNG paths have passed host adapter tests and
ARM builds. The corrected hardware diagnostic passed TRNG/DRBG stage 1 on the
user's board; Ed25519 execution remains to be verified.

The optional adapter feature `hashes` exposes one-shot SHA-1/SHA-224/SHA-256
and HMAC with each hash. OpenSK uses SHA-256 through its existing board API.
SHA-1/SHA-224 and HMAC vectors pass in the host driver model and corrected
hardware diagnostic stage 2.

The `aes128` adapter feature exposes ECB/CBC (without padding), CTR, CMAC,
CBC-MAC and CCM with 7–13-byte nonces and 4–16-byte even-length tags.
The runner feature `hardware-crypto-aes128-ccm` selects CC310 CCM for the
existing board API; it is mutually exclusive with the BLE CCM peripheral.
`cc310-primitives` enables the additional hash and AES APIs. It does not add
WebAuthn algorithms. NIST AES/CMAC vectors, round trips and tampered-tag/error
handling pass in the host model; physical-device execution is pending.

The `chacha20poly1305` adapter feature provides the IETF AEAD format
(256-bit key, 12-byte nonce, 16-byte tag). It preserves caller output on
failed authentication. RFC8439 and tampered-tag checks pass in the host model;
hardware execution is pending. The pinned PSA interface does not expose
the legacy 128-bit ChaCha key format.

The `x25519` adapter feature exposes key generation, public derivation and
ECDH in RFC7748 little-endian form. All-zero shared secrets are rejected.
RFC7748 cross-party and low-order checks pass in the host model; hardware
execution is pending. OpenSK credential algorithms are unchanged.

The `ecc` adapter feature exposes NIST P-192/P-224/P-256/P-384,
secp192k1/secp224k1/secp256k1 and BrainpoolP256r1 keygen, SEC1 public keys,
ECDSA prehash and ECDH. Host OpenSSL cross-checks cover all eight curves.
secp224k1 uses 29-byte private/signature scalars and 28-byte coordinates/ECDH
outputs; Nordic's pinned mapper selects it using field bits 224.
The pinned PSA binary rejects 160-bit and P-521 domain mappings; these curves
are not exposed. SHA-384/SHA-512 digests may be supplied to ECDSA externally,
but their hash computation is not a CC310 hardware path. Hardware execution
of the additional curves is pending. Host tests require OpenSSL development headers.

The `rsa` adapter feature provides 1024/1536/2048-bit key generation,
PKCS#1 DER public/private keys, SHA-256 PKCS#1 v1.5/PSS signatures and
PKCS#1 v1.5/OAEP-SHA256 encryption/decryption. Secret DER and plaintext
buffers are zeroized. RSA-2048 host OpenSSL round trips and rejection checks
pass; physical-device RSA execution is pending.

The ARM-only `srp` adapter feature provides Nordic legacy SRP-6a/SHA-256
contexts for trusted 1024/1536/2048/3072-bit groups, random salt/verifiers,
ephemeral public keys, session keys and mutual proofs. It uses the same
v0.9.19 legacy/core libraries and CC310 SHA-256 hooks; secret contexts are wiped.
ABI assertions match the pinned 1020-byte SRP context. SRP has passed ARM
compilation and full linking; its cryptographic execution is still pending.

Build the single hardware diagnostic image with
`./tools/build_cc310_tests.sh --self-test-only`. It writes
`build/hw-crypto/nordic-self-test.uf2` and halts after RAM-only checks.
Repeated green blinking means all stages passed. Red bursts indicate the
failed stage, followed by blue bursts for a substep when available: 1 TRNG/DRBG, 2 hashes/HMAC, 3 AES-128, 4 Ed25519, 5 X25519,
6 additional ECC, 7 RSA, 8 SRP-3072, 9 ChaCha20-Poly1305. A hang leaves the
active stage color; RTT logs provide the stage and error. The diagnostic image
has no FIDO event loop; restore the normal OpenSK UF2 after recording its result.
Hash substeps are 1 SHA-1, 2 SHA-224, 3 SHA-256, 4 HMAC-SHA1,
5 long-key HMAC-SHA224. AES substeps are 1 ECB, 2 CBC, 3 CTR, 4 CMAC,
5 CBC-MAC, 6 CCM, 7 tagless CCM*, 8 tampered CCM tag. ECC substeps follow the
eight-curve order listed above.
No hardware execution is implied by successfully building this image.

`aes128::ccm_star_no_tag` provides CCM* with a 13-byte nonce and no MAC,
using the CC310 AES-CTR payload stream. Its ciphertext matches authenticated
CCM for the same key/nonce. It is included in hardware self-test stage 3.

SRP contexts become unusable and are wiped after a driver failure. This prevents
subsequent calls from dereferencing callback pointers cleared by Nordic.

Direct entropy uses Nordic's platform wrapper, including its RNG mutex and
CC310 power handling. Calling the PSA entropy function directly left the
hardware diagnostic at a static red stage 1; the corrected stage passed on
hardware.

CC310's DMA driver accepts RAM addresses only. Flash input is copied to a
wiped RAM buffer for hash/MAC, cipher and AEAD calls; existing RAM input keeps
the direct DMA path. This also handles fixed vectors and long HMAC keys.

The pinned PSA MAC function exposes CMAC but rejects CBC-MAC. Raw CBC-MAC
therefore uses CC310 CBC encryption with a zero IV and returns the final block,
without switching to software crypto.

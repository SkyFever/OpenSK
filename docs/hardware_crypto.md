# Makerdiary CC310 backend

The `--crypto=cc310` build uses Nordic CC310 for P-256, SHA-256 and
HMAC-SHA256, general RNG and the AES-128-CCM board API. AES-256-CBC keeps
the existing software backend because CC310 supports only 128-bit AES keys. Optional Ed25519 uses CC310 PKA with explicit software SHA-512.

| Operation | `software` | `cc310` |
| --- | --- | --- |
| P-256 keygen, public key, ECDSA, ECDH | RustCrypto | CC310 |
| SHA-256, HMAC-SHA256 | RustCrypto | CC310 |
| AES-128-CCM board API | nRF CCM peripheral or RustCrypto | CC310 |
| AES-256-CBC | RustCrypto | RustCrypto |
| Optional Ed25519 | RustCrypto | CC310 PKA + RustCrypto SHA-512 |
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
user's board. Ed25519 public/signature vectors, valid-signature verification,
changed-message rejection, fresh key generation/signing/verification and
private-key wiping also passed on hardware. The additional ECC, RSA, SRP
and ChaCha20-Poly1305 stages are still being verified.

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
handling pass in the host model and hardware diagnostic stage 3.

The `chacha20poly1305` adapter feature provides the IETF AEAD format
(256-bit key, 12-byte nonce, 16-byte tag). It preserves caller output on
failed authentication. RFC8439 and tampered-tag checks pass in the host model;
hardware execution is pending. The pinned PSA interface does not expose
the legacy 128-bit ChaCha key format.

The `x25519` adapter feature exposes key generation, public derivation and
ECDH in RFC7748 little-endian form. All-zero shared secrets are rejected.
RFC7748 cross-party and low-order checks pass in the host model. Public-key
and shared-secret vectors and all-zero-peer rejection passed on the user's
board; fresh key generation is not covered by that diagnostic stage.
OpenSK credential algorithms are unchanged.

The `ecc` adapter feature exposes NIST P-192/P-224/P-256/P-384,
secp192k1/secp224k1/secp256k1 and BrainpoolP256r1 keygen, SEC1 public keys,
ECDSA prehash and ECDH. Host OpenSSL cross-checks cover all eight curves.
secp224k1 uses 29-byte private/signature scalars and 28-byte coordinates/ECDH
outputs; Nordic's pinned mapper selects it using field bits 224.
The pinned PSA binary rejects 160-bit and P-521 domain mappings; these curves
are not exposed. SHA-384/SHA-512 digests may be supplied to ECDSA externally,
but their hash computation is not a CC310 hardware path. Hardware execution
has passed the full P-192, P-224, P-256, P-384 and secp192k1 stages.
secp224k1 public derivation, signing, verification, changed-digest rejection
and ECDH passed; its fresh key generation failed at stage 6 / curve 6 /
operation 6. Later curves have not yet run. Host tests require OpenSSL development headers.

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
5 CBC-MAC, 6 CCM, 7 tagless CCM*, 8 tampered CCM tag. ECC blue bursts follow
the eight-curve order listed above; an additional green burst identifies the
operation: 1 public derivation, 2 signing, 3 valid-signature verification,
4 changed-digest rejection, 5 ECDH/value check, 6 fresh key generation,
7 fresh public derivation. P-192 additionally checks its d=1 public key
against G at operation 1, then verifies independent fixed signatures before
operation 3: 8 uses Q=2G, 9 uses Q=G, 10 uses Q=-G. These signatures use
d=2, d=1 or d=n-1, nonce k=1, and the SHA-256 prehash 0x42 repeated 32 times.
The references were independently verified with host OpenSSL.
Before operation 9, additional P-192 checks retain the failed normalization
inputs as regression vectors:
11 compares CC310's d=2 public key against 2G; 12 verifies the original 2G
signature with an equivalent 64-byte prehash; 13 verifies the adjusted fixed
signature with a 32-byte prehash; 14 repeats that check with a 64-byte prehash.
The adjusted signature and both prehash encodings were checked independently
with OpenSSL. ECC verifier failures also append white bursts for the raw PSA
status: 1 invalid signature, 2 invalid argument, 3 not supported, 4 hardware
failure, 5 buffer too small, 6 corruption detected, 7 other error.
For example, red 6 / blue 1 / green 2 means P-192 signing failed.
Repeated green alone remains the all-stages-passed signal.
RTT logs also identify the ECC curve and operation separately.
Ed25519 substeps are 1 public derivation/vector,
2 signing, 3 signature vector, 4 verification, 5 changed-message rejection,
6 fresh seed generation, 7 fresh public derivation, 8 fresh signing,
9 fresh verification, 10 private-key wiping.
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

Nordic Ed25519 requests SHA-512 through the PSA hash wrapper hooks. The CC310
hash driver supports only SHA-1/SHA-224/SHA-256, so SHA-512 is selected explicitly
as software while the curve operations retain CC310 PKA. The state fits the
unchanged 240-byte driver context; unaligned copies preserve the Nordic ABI.
Previously the wrapper rejected the SHA-512 request during stage 4, substep 1.
The corrected hooks are cross-checked against host OpenSSL for one-shot and
streaming inputs around SHA-512 block/padding boundaries. The user's board
passed the corrected public/signature vectors and verification checks.


The pinned Nordic Ed25519 PSA verifier maps the core's signature mismatch
through its RSA error converter, returning a hardware failure instead of
PSA_ERROR_INVALID_SIGNATURE. The adapter calls the same CC310 core verifier
with its pinned 0x2f0-byte temporary context and preserves the raw result.
Only CC_EC_EDW_SIGN_VERIFY_FAILED_ERROR becomes an invalid signature; every
other nonzero result remains an error. The native C shim regression uses
a stub core to check success, mismatch, unrelated failure, and buffer/ABI
arguments without claiming to run CC310 hardware:
python3 tools/test_cc310_ed25519.py.

Ed25519 private keys retain their 32-byte RFC8032 seed format. The pinned
Nordic PSA key-generation branch copies a generated seed without setting the
output-length pointer, so the adapter's length check rejected a successful
call. Seed generation now uses the existing CC310 TRNG-seeded AES CTR-DRBG
directly under the Rust driver guard; public derivation and signatures still
use CC310 PKA with explicit software SHA-512. The native C regression also
checks exact seed length, DRBG initialization failure, generation failure
and short output.

The user's board passed the independent P-192 Q=2G signature but rejected
the independently verified Q=G signature (stage 6 / curve 1 / operation 9).
The pinned core verifier precomputes G+Q through PkaAddAff, whose instruction
path has no equal-point branch. An initial Q'=2Q, e'=2e, s'=2s normalization
preserved the verification equation but still failed on the board.

The board then passed its d=2 public derivation and an equivalent 64-byte
prehash (operations 11 and 12), but rejected the independent transformed
Q=2G signature at operation 13 with PSA_ERROR_INVALID_SIGNATURE (white 1).
For that vector, a scalar-coefficient replay of the core's binary joint
multiplication reaches -G+G=infinity at bit 1 before returning to G.
PkaAddJcbAfn2Mdf also has no equal/opposite-point branch. Changing only the
precomputed point does not avoid this intermediate exceptional addition.

For exact Q=dG with d in {1,-1,2,-2}, the adapter now computes the public
scalar z=(e+d*r)/s mod n, asks CC310 to derive R=zG, and checks R.x mod n=r.
This uses one hardware point multiplication instead of the affected joint
multiplication. A zero z rejects the infinity result before a driver call.
Both coordinates must match the independently derived known public point;
the adapter does not infer d from an x coordinate alone.

Signature scalar bounds are checked before reduction. Binary extended GCD
and modular multiplication prepare public inputs in C; the curve operation
still runs on CC310. This is a hybrid verification path for the four known
points, not a fully hardware scalar calculation. Driver/length/SEC1-prefix
failures propagate. Other public keys retain the Nordic verifier. The
implementation covers the demonstrated known-point failures; it does not
establish completeness of the pinned core's addition formulas for other keys.
bits2int truncation is preserved, including secp224k1's 225-bit order.
This applies to all eight curves and the existing P-256 board API.

python3 tools/test_cc310_ecc.py exercises the actual C shim with an OpenSSL
driver stub that refuses joint verification for G, -G, 2G and -2G.
It checks 600 random-nonce and 480 fixed-nonce valid signatures across eight
curves, five keys, five digest lengths and three digest patterns, plus
changed digests, ignored digest suffixes, scalar bounds, infinity rejection,
unchanged inputs and driver/length/prefix failures. The fifth key (3G) checks
that ordinary keys retain the driver path. Curve constants are independently
derived with OpenSSL, and the original domain constants match the pinned
CC310 ELF domains. The user's board passed the replacement P-192 fixed
signatures, including the previously failing operation 13, Q=G and Q=-G.
It then completed the first five ECC curves and reached secp224k1 fresh key
generation (stage 6 / curve 6 / operation 6). The single-point path also
passed secp224k1's generated signature with its 225-bit scalar order.

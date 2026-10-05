#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual C verification shim with an OpenSSL-backed driver stub."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CC310 = ROOT / "third_party/wasefire/crates/runner-nordic/crates/cc310"
CACHE = ROOT / "third_party/wasefire/.root/cc310"

HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <psa/crypto.h>
#include <cc3xx_psa_key_generation.h>
#include <cc3xx_psa_asymmetric_signature.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

static const int nids[8] = {
    NID_X9_62_prime192v1, NID_secp224r1, NID_X9_62_prime256v1, NID_secp384r1,
    NID_secp192k1, NID_secp224k1, NID_secp256k1, NID_brainpoolP256r1
};
static int export_status, verify_status;
static int short_export, bad_export;
static unsigned export_calls, verify_calls;
int opensk_cc310_ecc_verify(uint32_t curve, const uint8_t *key, size_t key_size,
    const uint8_t *hash, size_t hash_size, const uint8_t *sig, size_t sig_size);
int opensk_cc310_verify(const uint8_t key[64], const uint8_t digest[32], const uint8_t sig[64]);

static int curve_id(const psa_key_attributes_t *attr)
{
    psa_ecc_family_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(psa_get_key_type(attr));
    size_t bits = psa_get_key_bits(attr);
    if (family == PSA_ECC_FAMILY_SECP_R1) {
        if (bits == 192) return 0;
        if (bits == 224) return 1;
        if (bits == 256) return 2;
        if (bits == 384) return 3;
    }
    if (family == PSA_ECC_FAMILY_SECP_K1) {
        if (bits == 192) return 4;
        if (bits == 224) return 5;
        if (bits == 256) return 6;
    }
    assert(family == PSA_ECC_FAMILY_BRAINPOOL_P_R1 && bits == 256);
    return 7;
}

psa_status_t cc3xx_export_public_key(const psa_key_attributes_t *attr,
    const uint8_t *key, size_t key_size, uint8_t *output, size_t size, size_t *written)
{
    export_calls++;
    if (export_status) return export_status;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nids[curve_id(attr)]);
    EC_POINT *point = EC_POINT_new(group);
    BIGNUM *scalar = BN_bin2bn(key, (int)key_size, NULL);
    assert(EC_POINT_mul(group, point, scalar, NULL, NULL, NULL) == 1);
    *written = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                  output, size, NULL);
    assert(*written == size);
    if (short_export) (*written)--;
    if (bad_export) output[0] = 0;
    BN_free(scalar);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return PSA_SUCCESS;
}

psa_status_t cc3xx_verify_hash(const psa_key_attributes_t *attr,
    const uint8_t *key, size_t key_size, psa_algorithm_t algorithm,
    const uint8_t *hash, size_t hash_size, const uint8_t *signature, size_t sig_size)
{
    verify_calls++;
    if (verify_status) return verify_status;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nids[curve_id(attr)]);
    EC_POINT *point = EC_POINT_new(group);
    EC_POINT *negative = EC_POINT_dup(EC_GROUP_get0_generator(group), group);
    assert(EC_POINT_invert(group, negative, NULL) == 1);
    assert(EC_POINT_oct2point(group, point, key, key_size, NULL) == 1);
    /* Known small multiples must use the complete single-multiplication path. */
    assert(EC_POINT_cmp(group, point, EC_GROUP_get0_generator(group), NULL) != 0);
    assert(EC_POINT_cmp(group, point, negative, NULL) != 0);
    EC_POINT *doubled = EC_POINT_new(group);
    assert(EC_POINT_dbl(group, doubled, EC_GROUP_get0_generator(group), NULL) == 1);
    assert(EC_POINT_cmp(group, point, doubled, NULL) != 0);
    assert(EC_POINT_invert(group, doubled, NULL) == 1);
    assert(EC_POINT_cmp(group, point, doubled, NULL) != 0);
    EC_POINT_free(doubled);
    assert(export_calls == 0);
    assert(PSA_ALG_IS_ECDSA(algorithm));
    EC_KEY *public_key = EC_KEY_new();
    assert(EC_KEY_set_group(public_key, group) == 1);
    assert(EC_KEY_set_public_key(public_key, point) == 1);
    ECDSA_SIG *sig = ECDSA_SIG_new();
    assert(ECDSA_SIG_set0(sig, BN_bin2bn(signature, (int)sig_size / 2, NULL),
                          BN_bin2bn(signature + sig_size / 2, (int)sig_size / 2, NULL)) == 1);
    int valid = ECDSA_do_verify(hash, (int)hash_size, sig, public_key);
    assert(valid >= 0);
    ECDSA_SIG_free(sig);
    EC_KEY_free(public_key);
    EC_POINT_free(negative);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return valid ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;
}

static void reset_calls(void) { export_calls = verify_calls = 0; }
static void add_one(uint8_t *value, size_t size)
{
    while (size && ++value[--size] == 0) {}
}

int main(void)
{
    unsigned cases = 0, fixed_cases = 0;
    const size_t hashes[] = {20, 28, 32, 48, 64};
    for (uint32_t curve = 0; curve < 8; curve++) {
        EC_GROUP *group = EC_GROUP_new_by_curve_name(nids[curve]);
        BIGNUM *order = BN_new(), *scalar = BN_new();
        assert(EC_GROUP_get_order(group, order, NULL) == 1);
        size_t size = (size_t)BN_num_bytes(order);
        size_t coordinate = ((size_t)EC_GROUP_get_degree(group) + 7) / 8;
        uint8_t order_bytes[48], point_bytes[97], signature[96], saved_sig[96];
        uint8_t digest[64], changed[64], saved_point[97];
        assert(BN_bn2binpad(order, order_bytes, (int)size) == (int)size);
        for (unsigned which = 0; which < 5; which++) {
            if (which == 0) assert(BN_one(scalar) == 1);
            if (which == 1) {
                assert(BN_copy(scalar, order));
                assert(BN_sub_word(scalar, 1) == 1);
            }
            if (which == 2) assert(BN_set_word(scalar, 2) == 1);
            if (which == 3) {
                assert(BN_copy(scalar, order));
                assert(BN_sub_word(scalar, 2) == 1);
            }
            if (which == 4) assert(BN_set_word(scalar, 3) == 1);
            EC_POINT *point = EC_POINT_new(group);
            assert(EC_POINT_mul(group, point, scalar, NULL, NULL, NULL) == 1);
            EC_KEY *key = EC_KEY_new();
            assert(EC_KEY_set_group(key, group) == 1);
            assert(EC_KEY_set_private_key(key, scalar) == 1);
            assert(EC_KEY_set_public_key(key, point) == 1);
            size_t public_size = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                                   point_bytes, sizeof(point_bytes), NULL);
            assert(public_size == 1 + 2 * coordinate);
            memcpy(saved_point, point_bytes, public_size);
            for (size_t h = 0; h < sizeof(hashes)/sizeof(hashes[0]); h++) {
                size_t hash_size = hashes[h];
                for (unsigned pattern = 0; pattern < 3; pattern++) {
                    memset(digest, pattern == 0 ? 0 : pattern == 1 ? 0x42 : 0xff, hash_size);
                    ECDSA_SIG *sig = ECDSA_do_sign(digest, (int)hash_size, key);
                    assert(sig);
                    const BIGNUM *r, *s;
                    ECDSA_SIG_get0(sig, &r, &s);
                    assert(BN_bn2binpad(r, signature, (int)size) == (int)size);
                    assert(BN_bn2binpad(s, signature + size, (int)size) == (int)size);
                    memcpy(saved_sig, signature, 2 * size);
                    reset_calls();
                    assert(opensk_cc310_ecc_verify(curve, point_bytes, public_size,
                        digest, hash_size, signature, 2 * size) == PSA_SUCCESS);
                    assert(export_calls == (which == 4 ? 0u : 1u));
                    assert(verify_calls == (which == 4 ? 1u : 0u));
                    memcpy(changed, digest, hash_size);
                    changed[0] ^= 0x80;
                    reset_calls();
                    assert(opensk_cc310_ecc_verify(curve, point_bytes, public_size,
                        changed, hash_size, signature, 2 * size) == PSA_ERROR_INVALID_SIGNATURE);
                    if (hash_size * 8 > (size_t)BN_num_bits(order)) {
                        memcpy(changed, digest, hash_size);
                        changed[hash_size - 1] ^= 1;
                        reset_calls();
                        assert(opensk_cc310_ecc_verify(curve, point_bytes, public_size,
                            changed, hash_size, signature, 2 * size) == PSA_SUCCESS);
                    }
                    if (which != 4) {
                        for (size_t half = 0; half < 2; half++) {
                            for (unsigned invalid = 0; invalid < 3; invalid++) {
                                memcpy(signature, saved_sig, 2 * size);
                                if (invalid == 0) memset(signature + half * size, 0, size);
                                else {
                                    memcpy(signature + half * size, order_bytes, size);
                                    if (invalid == 2) add_one(signature + half * size, size);
                                }
                                reset_calls();
                                assert(opensk_cc310_ecc_verify(curve, point_bytes, public_size,
                                    digest, hash_size, signature, 2 * size) == PSA_ERROR_INVALID_SIGNATURE);
                                assert(export_calls == 0 && verify_calls == 0);
                            }
                        }
                        memcpy(signature, saved_sig, 2 * size);
                        export_status = PSA_ERROR_HARDWARE_FAILURE;
                        reset_calls();
                        assert(opensk_cc310_ecc_verify(curve, point_bytes, public_size,
                            digest, hash_size, signature, 2 * size) == export_status);
                        assert(export_calls == 1 && verify_calls == 0);
                        export_status = 0;
                        short_export = 1;
                        reset_calls();
                        assert(opensk_cc310_ecc_verify(curve, point_bytes, public_size,
                            digest, hash_size, signature, 2 * size) == PSA_ERROR_CORRUPTION_DETECTED);
                        short_export = 0;
                        bad_export = 1;
                        reset_calls();
                        assert(opensk_cc310_ecc_verify(curve, point_bytes, public_size,
                            digest, hash_size, signature, 2 * size) == PSA_ERROR_CORRUPTION_DETECTED);
                        bad_export = 0;
                    } else {
                        verify_status = PSA_ERROR_HARDWARE_FAILURE;
                        reset_calls();
                        assert(opensk_cc310_ecc_verify(curve, point_bytes, public_size,
                            digest, hash_size, signature, 2 * size) == verify_status);
                        assert(verify_calls == 1);
                        verify_status = 0;
                    }
                    assert(memcmp(signature, saved_sig, 2 * size) == 0);
                    assert(memcmp(point_bytes, saved_point, public_size) == 0);
                    for (size_t i = 0; i < hash_size; i++) {
                        assert(digest[i] == (pattern == 0 ? 0 : pattern == 1 ? 0x42 : 0xff));
                    }
                    if (curve == 2 && hash_size == 32) {
                        reset_calls();
                        assert(opensk_cc310_verify(point_bytes + 1, digest, signature) == PSA_SUCCESS);
                    }
                    ECDSA_SIG_free(sig);
                    cases++;
                    if (which != 4) {
                        // Independent k=1 signatures include the physical failure's R=G.
                        BN_CTX *ctx = BN_CTX_new();
                        BIGNUM *e = BN_bin2bn(digest, (int)hash_size, NULL);
                        BIGNUM *x = BN_new(), *fixed_r = BN_new(), *fixed_s = BN_new();
                        assert(EC_POINT_get_affine_coordinates(group,
                            EC_GROUP_get0_generator(group), x, NULL, ctx) == 1);
                        assert(BN_nnmod(fixed_r, x, order, ctx) == 1);
                        int excess = (int)(8 * hash_size) - BN_num_bits(order);
                        if (excess > 0) assert(BN_rshift(e, e, excess) == 1);
                        assert(BN_mod_mul(fixed_s, fixed_r, scalar, order, ctx) == 1);
                        assert(BN_mod_add(fixed_s, fixed_s, e, order, ctx) == 1);
                        assert(!BN_is_zero(fixed_s));
                        assert(BN_bn2binpad(fixed_r, signature, (int)size) == (int)size);
                        assert(BN_bn2binpad(fixed_s, signature + size, (int)size) == (int)size);
                        ECDSA_SIG *fixed = ECDSA_SIG_new();
                        assert(ECDSA_SIG_set0(fixed, BN_dup(fixed_r), BN_dup(fixed_s)) == 1);
                        assert(ECDSA_do_verify(digest, (int)hash_size, fixed, key) == 1);
                        reset_calls();
                        assert(opensk_cc310_ecc_verify(curve, point_bytes, public_size,
                            digest, hash_size, signature, 2 * size) == PSA_SUCCESS);
                        assert(export_calls == 1 && verify_calls == 0);
                        fixed_cases++;
                        // e=-d*r gives R=infinity and must reject before a driver call.
                        assert(BN_mod_mul(e, fixed_r, scalar, order, ctx) == 1);
                        assert(BN_sub(e, order, e) == 1);
                        memset(signature + size, 0, size);
                        signature[2 * size - 1] = 1;
                        uint8_t zero_point_hash[64] = {0};
                        int order_bits = BN_num_bits(order);
                        int padding = (int)(8 * size) - order_bits;
                        if (padding) assert(BN_lshift(e, e, padding) == 1);
                        assert(BN_bn2binpad(e, zero_point_hash, (int)size) == (int)size);
                        reset_calls();
                        assert(opensk_cc310_ecc_verify(curve, point_bytes, public_size,
                            zero_point_hash, 64, signature, 2 * size) == PSA_ERROR_INVALID_SIGNATURE);
                        assert(export_calls == 0 && verify_calls == 0);
                        ECDSA_SIG_free(fixed);
                        BN_free(e); BN_free(x); BN_free(fixed_r); BN_free(fixed_s);
                        BN_CTX_free(ctx);
                    }
                }
            }
            EC_KEY_free(key);
            EC_POINT_free(point);
        }
        BN_free(scalar);
        BN_free(order);
        EC_GROUP_free(group);
    }
    printf("Actual C shim: %u random-nonce and %u fixed-nonce valid cases across "
           "8 curves, 5 keys and 5 digest lengths; changed inputs, scalar bounds, "
           "infinity and driver errors passed.\n", cases, fixed_cases);
    return 0;
}
"""


class EccShimTest(unittest.TestCase):
    def test_basepoint_verification_against_openssl(self):
        includes = [
            CC310 / "src",
            CACHE / "mbedtls/include",
            CACHE / "nrfxlib/crypto/nrf_cc310_mbedcrypto/include",
            CACHE / "nrfxlib/crypto/nrf_cc310_platform/include",
        ]
        with tempfile.TemporaryDirectory(prefix="opensk-ecc-shim-") as temp:
            temp = Path(temp)
            harness, binary = temp / "verify.c", temp / "verify"
            harness.write_text(HARNESS)
            command = [
                "clang-18", "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
                "-Wno-deprecated-declarations", "-ffunction-sections", "-fdata-sections",
                '-DMBEDTLS_CONFIG_FILE="cc310_config.h"',
            ]
            for directory in includes:
                command += ["-I", str(directory)]
            command += [
                str(CC310 / "src/cc310.c"), str(harness),
                "-Wl,--gc-sections", "-lcrypto", "-o", str(binary),
            ]
            subprocess.run(command, check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the actual Ed25519 C shim against stub core and CTR-DRBG APIs."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CC310 = ROOT / "third_party/wasefire/crates/runner-nordic/crates/cc310"
CACHE = ROOT / "third_party/wasefire/.root/cc310"

HARNESS = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <psa/crypto.h>
#include <nrf_cc3xx_platform_ctr_drbg.h>
#include <mbedtls_extra/mbedtls_cc_ec_mont_edw_error.h>

static uint32_t core_result;
static const uint8_t *expected_message;
static size_t expected_size;
static unsigned calls;
int opensk_cc310_ed25519_verify(const uint8_t public_key[32],
    const uint8_t *message, size_t message_size, const uint8_t signature[64]);

uint32_t CC_EcEdwVerify(const uint8_t *signature, size_t signature_size,
    const uint8_t *public_key, size_t public_key_size,
    const uint8_t *message, size_t message_size, void *temporary)
{
    assert(signature && signature_size == 64);
    assert(public_key && public_key_size == 32);
    assert(message == expected_message && message_size == expected_size);
    assert((uintptr_t)temporary % 8 == 0);
    uint32_t *words = temporary;
    for (size_t i = 0; i < 188; i++) assert(words[i] == 0);
    words[187] = 0xdeadbeef;
    calls++;
    return core_result;
}

static int init_result, random_result;
static unsigned init_calls, free_calls, random_calls;
static int short_output;
static uint8_t *expected_seed;
int opensk_cc310_ed25519_generate(uint8_t seed[32]);

int nrf_cc3xx_platform_ctr_drbg_init(
    nrf_cc3xx_platform_ctr_drbg_context_t * const context,
    const uint8_t *personalization, size_t size)
{
    assert(context && !context->is_initialized);
    assert(size == strlen("OpenSK nRF52840 CC310"));
    assert(memcmp(personalization, "OpenSK nRF52840 CC310", size) == 0);
    init_calls++;
    if (!init_result) context->is_initialized = 1;
    return init_result;
}

int nrf_cc3xx_platform_ctr_drbg_free(
    nrf_cc3xx_platform_ctr_drbg_context_t * const context)
{
    memset(context, 0, sizeof(*context));
    free_calls++;
    return 0;
}

int nrf_cc3xx_platform_ctr_drbg_get(
    nrf_cc3xx_platform_ctr_drbg_context_t * const context,
    uint8_t *output, size_t size, size_t *written)
{
    assert(context && context->is_initialized);
    assert(output == expected_seed && size == 32);
    random_calls++;
    *written = short_output ? size - 1 : size;
    for (size_t i = 0; i < *written; i++) output[i] = (uint8_t)(i + 1);
    return random_result;
}

static void test_seed_generation(void)
{
    uint8_t buffer[34];
    memset(buffer, 0xa5, sizeof(buffer));
    expected_seed = buffer + 1;
    init_result = -1;
    assert(opensk_cc310_ed25519_generate(expected_seed) == PSA_ERROR_INSUFFICIENT_ENTROPY);
    for (size_t i = 0; i < sizeof(buffer); i++) assert(buffer[i] == 0xa5);
    assert(init_calls == 1 && free_calls == 1 && random_calls == 0);
    init_result = 0;
    assert(opensk_cc310_ed25519_generate(expected_seed) == PSA_SUCCESS);
    for (size_t i = 0; i < 32; i++) assert(expected_seed[i] == i + 1);
    random_result = -1;
    assert(opensk_cc310_ed25519_generate(expected_seed) == PSA_ERROR_INSUFFICIENT_ENTROPY);
    random_result = 0;
    short_output = 1;
    assert(opensk_cc310_ed25519_generate(expected_seed) == PSA_ERROR_INSUFFICIENT_ENTROPY);
    assert(init_calls == 2 && free_calls == 1 && random_calls == 3);
    assert(buffer[0] == 0xa5 && buffer[33] == 0xa5);
}

int main(void)
{
    test_seed_generation();
    const uint8_t public_key[32] = {1}, signature[64] = {2}, message[] = {0x72};
    expected_message = message;
    expected_size = sizeof(message);
    core_result = 0;
    assert(opensk_cc310_ed25519_verify(public_key, message, 1, signature) == PSA_SUCCESS);
    core_result = CC_EC_EDW_SIGN_VERIFY_FAILED_ERROR;
    assert(opensk_cc310_ed25519_verify(public_key, message, 1, signature)
        == PSA_ERROR_INVALID_SIGNATURE);
    core_result = CC_ECEDW_INTERNAL_ERROR;
    assert(opensk_cc310_ed25519_verify(public_key, message, 1, signature)
        == PSA_ERROR_HARDWARE_FAILURE);
    core_result = CC_EC_EDW_INVALID_INPUT_SIZE_ERROR;
    assert(opensk_cc310_ed25519_verify(public_key, message, 1, signature)
        == PSA_ERROR_HARDWARE_FAILURE);
    expected_message = NULL;
    expected_size = 0;
    core_result = 0;
    assert(opensk_cc310_ed25519_verify(public_key, message, 0, signature) == PSA_SUCCESS);
    assert(calls == 5);
    return 0;
}
"""


class Ed25519ShimTest(unittest.TestCase):
    def test_seed_generation_and_verification_abi(self):
        includes = [
            CC310 / "src",
            CACHE / "mbedtls/include",
            CACHE / "nrfxlib/crypto/nrf_cc310_mbedcrypto/include",
            CACHE / "nrfxlib/crypto/nrf_cc310_platform/include",
        ]
        with tempfile.TemporaryDirectory(prefix="opensk-ed25519-shim-") as temp:
            temp = Path(temp)
            harness = temp / "verify.c"
            binary = temp / "verify"
            harness.write_text(HARNESS)
            command = [
                "clang-18", "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
                "-ffunction-sections", "-fdata-sections",
                '-DMBEDTLS_CONFIG_FILE="cc310_config.h"',
            ]
            for directory in includes:
                command += ["-I", str(directory)]
            command += [
                str(CC310 / "src/cc310.c"), str(harness),
                "-Wl,--gc-sections", "-o", str(binary),
            ]
            subprocess.run(command, check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the actual Ed25519 C shim's status mapping with a stub core."""
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
#include <psa/crypto.h>
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

int main(void)
{
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
    def test_raw_verification_status_and_abi(self):
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

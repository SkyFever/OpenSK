# SPDX-License-Identifier: Apache-2.0
import hashlib
from types import SimpleNamespace
import unittest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.hashes import SHA256
from fido2 import cose
from fido2.webauthn import AuthenticatorData
from crypto_hil import choose, signature_label, verify_assertion


class HostContractTests(unittest.TestCase):
    def test_device_selection_requires_unique_vid_pid_and_serial(self):
        one = SimpleNamespace(vid=0x18D1, pid=0x0239, serial_number="one")
        two = SimpleNamespace(vid=0x18D1, pid=0x0239, serial_number="two")
        wrong = SimpleNamespace(vid=0x1050, pid=0x0407, serial_number="one")
        self.assertIs(choose([one, two, wrong], 0x18D1, 0x0239, "one"), one)
        for devices in ([], [one, two]):
            with self.assertRaises(ValueError):
                choose(devices, 0x18D1, 0x0239, None)

    def test_assertion_checks_rp_credential_presence_uv_and_signature(self):
        key = ec.generate_private_key(ec.SECP256R1())
        state = {"rp_id": "test.local", "credential_id": b"test-id",
                 "public_key": dict(cose.ES256.from_cryptography_key(key.public_key()))}
        digest = hashlib.sha256(b"client").digest()
        def response(rp="test.local", flags=5, credential=b"test-id"):
            auth = AuthenticatorData.create(hashlib.sha256(rp.encode()).digest(), flags, 1)
            signature = key.sign(bytes(auth) + digest, ec.ECDSA(SHA256()))
            return SimpleNamespace(auth_data=auth, signature=signature, credential={"id": credential})
        verify_assertion(state, response(), digest, True)
        for bad in [response(rp="wrong.local"), response(flags=4),
                    response(flags=1), response(credential=b"wrong")]:
            with self.assertRaises(ValueError):
                verify_assertion(state, bad, digest, True)
        with self.assertRaises(InvalidSignature):
            verify_assertion(state, response(), b"x" * 32, True)

    def test_ed25519_assertion_and_tampered_signature(self):
        key = ed25519.Ed25519PrivateKey.generate()
        state = {"rp_id": "ed25519.local", "credential_id": b"ed-id",
                 "public_key": dict(cose.EdDSA.from_cryptography_key(key.public_key()))}
        digest = hashlib.sha256(b"client").digest()
        auth = AuthenticatorData.create(hashlib.sha256(b"ed25519.local").digest(), 1, 1)
        signature = key.sign(bytes(auth) + digest)
        response = SimpleNamespace(auth_data=auth, signature=signature,
                                   credential={"id": b"ed-id"})
        self.assertEqual(signature_label(state), "Ed25519")
        verify_assertion(state, response, digest, False)
        response.signature = signature[:-1] + bytes([signature[-1] ^ 1])
        with self.assertRaises(InvalidSignature):
            verify_assertion(state, response, digest, False)


if __name__ == "__main__":
    unittest.main()

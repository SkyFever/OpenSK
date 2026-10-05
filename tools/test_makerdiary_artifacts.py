# SPDX-License-Identifier: Apache-2.0
import struct
import tempfile
from pathlib import Path
import unittest
from makerdiary_artifacts import hex_record, patch_hex, read_hex, verify_uf2, S132_CLEAR


class MakerdiaryArtifactTests(unittest.TestCase):
    def image(self, extra=()):
        return "\n".join([hex_record(0x1000, 0, b"\x01\x02\x03\x04"), *extra, ":00000001FF"]) + "\n"

    def patch(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "platform.hex"
            path.write_text(text)
            status = patch_hex(path)
            result = path.read_text()
            self.assertEqual(patch_hex(path), "already present")
            self.assertEqual(path.read_text(), result)
            return status, result

    def test_sparse_metadata_is_explicit_and_existing_bytes_are_preserved(self):
        original = self.image()
        status, patched = self.patch(original)
        self.assertEqual(status, "inserted")
        before, after = read_hex(original), read_hex(patched)
        self.assertTrue(all(after[k] == v for k, v in before.items()))
        self.assertEqual(bytes(after[a] for a in range(0x3000, 0x3010)), S132_CLEAR)

    def test_segment_address_extension_does_not_alias_0x3000(self):
        _, patched = self.patch(self.image([
            hex_record(0, 2, b"\x08\x00"), hex_record(0x3000, 0, b"code")
        ]))
        memory = read_hex(patched)
        self.assertEqual(bytes(memory[a] for a in range(0xB000, 0xB004)), b"code")
        self.assertEqual(bytes(memory[a] for a in range(0x3000, 0x3010)), S132_CLEAR)

    def test_linear_address_extension_is_reset(self):
        _, patched = self.patch(self.image([
            hex_record(0, 4, b"\x00\x01"), hex_record(0x3000, 0, b"code")
        ]))
        memory = read_hex(patched)
        self.assertEqual(bytes(memory[a] for a in range(0x13000, 0x13004)), b"code")
        self.assertEqual(bytes(memory[a] for a in range(0x3000, 0x3010)), S132_CLEAR)

    def test_overlap_with_code_or_old_magic_is_rejected_without_writing(self):
        for address, data in [(0x3000, b"code"), (0x3004, bytes.fromhex("dbe5b151")), (0x300F, b"x")]:
            original = self.image([hex_record(address, 0, data)])
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "platform.hex"
                path.write_text(original)
                with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                    patch_hex(path)
                self.assertEqual(path.read_text(), original)

    def test_bad_checksum_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "checksum"):
            read_hex(":0410000001020304FF\n:00000001FF\n")

    def test_conflicting_overlap_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "overlap"):
            read_hex(self.image([hex_record(0x1000, 0, b"xxxx")]))

    def test_uf2_requires_bootstrap_family_and_explicit_clear_metadata(self):
        def block(address, payload, number, count, family=0xADA52840):
            header = struct.pack("<8I", 0x0A324655, 0x9E5D5157, 0x2000,
                                 address, len(payload), number, count, family)
            return header + payload + bytes(476 - len(payload)) + struct.pack("<I", 0x0AB16F30)
        valid = block(0x1000, b"boot", 0, 2) + block(0x3000, bytes(16), 1, 2)
        invalid = [
            block(0x3000, bytes(16), 0, 2) + block(0x8000, b"runner", 1, 2),
            block(0x1000, b"boot", 0, 1),
            block(0x1000, b"boot", 0, 2, family=0) + block(0x3000, bytes(16), 1, 2),
            block(0x1000, b"boot", 0, 2) + block(0x3000, bytes(4) + bytes.fromhex("dbe5b151") + bytes(8), 1, 2),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "platform.uf2"
            path.write_bytes(valid)
            self.assertEqual(verify_uf2(path)["s132_magic_word"], 0)
            for image in invalid:
                path.write_bytes(image)
                with self.assertRaises(ValueError):
                    verify_uf2(path)

    def test_runner_only_image_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "runner-only"):
            self.patch(hex_record(0x8000, 0, b"code") + "\n:00000001FF\n")


if __name__ == "__main__":
    unittest.main()

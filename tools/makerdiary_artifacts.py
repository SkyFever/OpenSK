#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Protect Makerdiary's stale S132 metadata without overwriting firmware."""
import argparse
from pathlib import Path
import struct

S132_ADDRESS = 0x3000
S132_SIZE = 16
S132_MAGIC = 0x51B1E5DB
S132_CLEAR = bytes(S132_SIZE)


def read_hex(text):
    memory = {}
    base = 0
    eof = False
    for number, line in enumerate(text.splitlines(), 1):
        if eof:
            raise ValueError(f"HEX data after EOF at line {number}")
        if not line.startswith(":"):
            raise ValueError(f"Invalid HEX line {number}")
        record = bytes.fromhex(line[1:])
        if len(record) < 5 or len(record) != record[0] + 5 or sum(record) & 255:
            raise ValueError(f"Invalid HEX length/checksum at line {number}")
        count, address, kind = record[0], int.from_bytes(record[1:3], "big"), record[3]
        data = record[4:4 + count]
        if kind == 0:
            for i, value in enumerate(data):
                position = base + address + i
                if position in memory and memory[position] != value:
                    raise ValueError(f"Conflicting HEX overlap at 0x{position:08x}")
                memory[position] = value
        elif kind == 1:
            if count or address:
                raise ValueError("Invalid HEX EOF")
            eof = True
        elif kind in (2, 4):
            if count != 2 or address:
                raise ValueError("Invalid HEX address extension")
            base = int.from_bytes(data, "big") << (4 if kind == 2 else 16)
        elif kind not in (3, 5):
            raise ValueError(f"Unsupported HEX record type {kind}")
    if not eof:
        raise ValueError("Missing HEX EOF")
    return memory


def hex_record(address, kind, data):
    raw = bytes([len(data)]) + address.to_bytes(2, "big") + bytes([kind]) + data
    return ":" + (raw + bytes([-sum(raw) & 255])).hex().upper()


def patch_hex(path):
    text = path.read_text(encoding="ascii")
    memory = read_hex(text)
    if not memory or min(memory) != 0x1000:
        raise ValueError("Refusing runner-only HEX: complete Makerdiary bootstrap required")
    occupied = {a: memory[a] for a in range(S132_ADDRESS, S132_ADDRESS + S132_SIZE) if a in memory}
    if occupied:
        if len(occupied) == S132_SIZE and bytes(occupied.values()) == S132_CLEAR:
            return "already present"
        raise ValueError(
            "S132 metadata patch overlaps actual artifact bytes at 0x3000..0x300f; "
            "refusing to overwrite Wasefire code/data"
        )
    # Reset either segment or linear base before appending the absolute address.
    lines = text.splitlines()
    lines[-1:-1] = [hex_record(0, 4, bytes(2)), hex_record(S132_ADDRESS, 0, S132_CLEAR)]
    result = "\n".join(lines) + "\n"
    after = read_hex(result)
    assert all(after[a] == value for a, value in memory.items())
    assert bytes(after[a] for a in range(S132_ADDRESS, S132_ADDRESS + S132_SIZE)) == S132_CLEAR
    path.write_text(result, encoding="ascii")
    return "inserted"


def verify_uf2(path):
    data = path.read_bytes()
    if not data or len(data) % 512:
        raise ValueError("Invalid UF2 size")
    memory = {}
    count = len(data) // 512
    for i in range(count):
        block = data[i * 512:(i + 1) * 512]
        m0, m1, flags, address, size, number, total, family = struct.unpack("<8I", block[:32])
        end, = struct.unpack("<I", block[508:])
        if (m0, m1, end) != (0x0A324655, 0x9E5D5157, 0x0AB16F30):
            raise ValueError(f"Invalid UF2 magic at block {i}")
        if not flags & 0x2000 or flags & 1 or family != 0xADA52840:
            raise ValueError(f"Invalid UF2 family/flags at block {i}")
        if (number, total) != (i, count) or size > 476:
            raise ValueError(f"Invalid UF2 block dimensions at block {i}")
        if address < 0x1000 or address + size > 0xE0000:
            raise ValueError(f"UF2 overlaps recovery bootloader, storage, or UICR at block {i}")
        for j, value in enumerate(block[32:32 + size]):
            position = address + j
            if position in memory and memory[position] != value:
                raise ValueError(f"Conflicting UF2 overlap at 0x{position:08x}")
            memory[position] = value
    try:
        metadata = bytes(memory[a] for a in range(S132_ADDRESS, S132_ADDRESS + S132_SIZE))
    except KeyError as error:
        raise ValueError("UF2 does not explicitly cover the S132 metadata region") from error
    if metadata != S132_CLEAR:
        raise ValueError("UF2 S132 metadata is not explicitly disabled")
    if min(memory) != 0x1000:
        raise ValueError("Refusing runner-only UF2")
    return {"blocks": count, "size": len(data), "s132_magic_word": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["patch-hex", "verify-uf2"])
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.operation == "patch-hex":
        print(f"Makerdiary S132 metadata: {patch_hex(args.path)} at 0x3000..0x300f")
    else:
        print(f"Makerdiary UF2/S132 verification: {verify_uf2(args.path)}")


if __name__ == "__main__":
    main()

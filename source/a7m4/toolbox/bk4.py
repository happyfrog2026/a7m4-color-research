"""Bounded, read-only BK4 record parsing; no firmware or hardware imports.

Extracted from a7m4/fl23.py::bk4_rows (MIT, A7M4 Fastboot Toolkit
contributors). Original source SHA-256:
93920a2e59af2cca261929b1e1508bbd8f20e235c89c70fa1270197ffa8d7f2f.
The existing repository LICENSE applies. No color-patching API is included.
"""
from __future__ import annotations

import struct

MAX_SETTINGS_BYTES = 32 * 1024 * 1024


class BK4Error(ValueError):
    """A settings record is malformed or outside the bounded BK4 format."""


def require(condition, code, message):
    if not condition:
        raise BK4Error(message)


def bk4_rows(data):
    """Parse two bounded BK4 containers and validate all records and sums."""
    require(isinstance(data, (bytes, bytearray)) and 0 < len(data) <= MAX_SETTINGS_BYTES,
            "BK4", "Settings must be bounded bytes")
    starts, pos = [], 0
    while True:
        pos = data.find(b"BK4\0", pos)
        if pos < 0:
            break
        if pos >= 12 and data[pos - 8:pos - 4] == b"\xaa" * 4:
            starts.append(pos - 12)
        pos += 4
    require(len(starts) == 2, "BK4", "Expected two BK4 segments")
    rows = []
    for number, base in enumerate(starts):
        end = starts[number + 1] if number + 1 < len(starts) else len(data)
        require(base + 0x100 <= end, "BK4", "Truncated header")
        groups, items, body = struct.unpack_from("<III", data, base + 0x10)
        extent = sum(struct.unpack_from("<II", data, base + 0x18))
        index = base + 0x100 + 6 * groups
        require(index + 6 * items <= base + body <= base + extent <= end, "BK4", "Invalid index or extent")
        checksum = sum(data[base:base + 0x20]) + sum(data[base + 0x24:base + extent])
        require(checksum == struct.unpack_from("<I", data, base + 0x20)[0], "BK4", "Original checksum mismatch")
        records, expected = {}, 0
        intervals = []
        for group in range(groups):
            count, first = struct.unpack_from("<HI", data, base + 0x100 + group * 6)
            require(first == expected and first + count <= items, "BK4", "Invalid group index")
            expected += count
            for slot in range(count):
                attrs, packed = struct.unpack_from("<HI", data, index + 6 * (first + slot))
                if packed == 0xffffffff:
                    continue
                offset, size = base + (packed & 0xffffff), packed >> 24
                start = offset
                if size == 255:
                    require(base + body <= offset <= base + extent - 2, "BK4", "Invalid extended record")
                    size = struct.unpack_from("<H", data, offset)[0]
                    offset += 2
                require(base + body <= start <= offset <= offset + size <= base + extent, "BK4", "Record outside body")
                records[(group << 16) | slot] = {"offset": offset, "size": size, "attrs": attrs}
                if offset + size > start:
                    intervals.append((start, offset + size))
        require(expected == items, "BK4", "Incomplete index")
        intervals.sort()
        require(all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])), "BK4", "Overlapping records")
        rows.append({"base": base, "extent": extent, "records": records})
    return rows


"""Bounded filter0 sound codec adapted from C2's offline native_codec.py.

Source: https://github.com/QAQLeonard/a7c2-fl23-research
File: src/shutter_sound/native_codec.py
Only filter0 is accepted here. A software decode is not a measured hardware
sample rate or independent hardware decoder proof. No source audio is included.

MIT License

Copyright (c) 2026 A7C II FL2/FL3 preview contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

This license covers newly authored software. Upstream software and Sony
firmware-derived data retain their respective rights; see upstream NOTICE.md.
"""
from __future__ import annotations

import math
from itertools import islice

BLOCK_BYTES = 32
SAMPLES_PER_BLOCK = 31
ALIGNMENT_BYTES = 64
HEADROOM = 32512
MAX_NATIVE_BYTES = 17600


def encoded_size(samples: int) -> int:
    if type(samples) is not int or not 1 <= samples <= 17050:
        raise ValueError("Native source sample count must be 1..17050")
    return 64 * ((samples + 61) // 62)


def encode_filter0(samples) -> bytes:
    """Encode once, requiring explicit caller gain/headroom; never normalize."""
    try:
        values = list(islice(iter(samples), 17051))
    except TypeError as exc:
        raise ValueError("Native samples must be a bounded iterable") from exc
    expected = encoded_size(len(values))
    if any(type(x) not in (int, float) or abs(x) > HEADROOM or not math.isfinite(x) for x in values):
        raise ValueError("Native PCM must be finite with explicit headroom within +/-32512")
    output = bytearray()
    for at in range(0, len(values), SAMPLES_PER_BLOCK):
        block = values[at:at + SAMPLES_PER_BLOCK]
        block += [0] * (SAMPLES_PER_BLOCK - len(block))
        exponent = next(n for n in range(9) if min(block) >= -128 * (1 << n) and max(block) <= 127 * (1 << n))
        step = 1 << exponent
        output.append(exponent)
        output.extend(max(-128, min(127, round(x / step))) & 255 for x in block)
    if len(output) % ALIGNMENT_BYTES:
        output.extend(bytes(BLOCK_BYTES))
    if len(output) != expected or len(output) > MAX_NATIVE_BYTES:
        raise ValueError("Encoded filter0 size exceeds its bounded format")
    return bytes(output)


def decode_filter0(raw: bytes) -> list[int]:
    """Decode all actual encoded blocks, including legitimate alignment silence."""
    if not isinstance(raw, bytes) or not raw or len(raw) % ALIGNMENT_BYTES or len(raw) > MAX_NATIVE_BYTES:
        raise ValueError("Native filter0 input must be 64-byte aligned and at most 17600 bytes")
    samples = []
    for at in range(0, len(raw), BLOCK_BYTES):
        control = raw[at]
        if control > 8:
            raise ValueError("Only filter0 exponent controls 0..8 are admitted")
        step = 1 << control
        for byte in raw[at + 1:at + BLOCK_BYTES]:
            sample = (byte if byte < 128 else byte - 256) * step
            if abs(sample) > HEADROOM:
                raise ValueError("Decoded native PCM exceeds the admitted +/-32512 headroom")
            samples.append(sample)
    return samples

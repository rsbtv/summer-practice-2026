#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TASK_DIR="$(dirname "$SCRIPT_DIR")"

python3 - "$TASK_DIR/resources/capture.bin" << 'PYEOF'
import sys, struct

path = sys.argv[1]
with open(path, "rb") as f:
    data = f.read()

def crc8(b: bytes) -> int:
    crc = 0
    for x in b:
        crc ^= x
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if (crc & 0x80) else (crc << 1) & 0xFF
    return crc

assert data[:8] == b"MBDUMP1\x00"
session_seed = data[8:12]
offset = 12

hidden = {}
while offset < len(data):
    rtype = data[offset]
    length = data[offset+1]
    payload = data[offset+2:offset+2+length]
    crc = data[offset+2+length]
    body = data[offset:offset+2+length]
    assert crc8(body) == crc, "CRC mismatch, corrupt record"
    if rtype == 0x7F:
        seq = payload[0]
        hidden[seq] = payload[1:]
    offset += 2 + length + 1

ordered = b"".join(hidden[k] for k in sorted(hidden))

state = int.from_bytes(session_seed, "big")
keystream = bytearray()
for _ in range(len(ordered)):
    state = (state * 1103515245 + 12345) & 0xFFFFFFFF
    keystream.append((state >> 16) & 0xFF)

flag = bytes(b ^ k for b, k in zip(ordered, keystream))
print(flag.decode())
PYEOF

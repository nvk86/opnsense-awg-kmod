#!/usr/bin/env python3
"""Validate AWG I1-I5 UDP packets captured in PCAP."""

import socket
import struct
import sys
import time

with open(sys.argv[1], "rb") as f:
    header = f.read(24)
    if len(header) != 24:
        sys.exit("FAIL: invalid PCAP header")

    magic = header[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    if magic not in formats:
        sys.exit("FAIL: unsupported PCAP format")

    endian = formats[magic]
    linktype = struct.unpack(endian + "I", header[20:24])[0]
    if linktype != 0:
        sys.exit(f"FAIL: unexpected linktype {linktype}")

    packets = []

    while True:
        record = f.read(16)
        if not record:
            break
        if len(record) != 16:
            sys.exit("FAIL: truncated PCAP record")

        _, _, captured, _ = struct.unpack(endian + "IIII", record)
        frame = f.read(captured)
        if len(frame) != captured:
            sys.exit("FAIL: truncated packet")

        if len(frame) < 32:
            continue

        family = struct.unpack(endian + "I", frame[:4])[0]
        if family != socket.AF_INET:
            continue

        ip = frame[4:]
        ihl = (ip[0] & 15) * 4
        if ihl < 20 or len(ip) < ihl + 8 or ip[9] != 17:
            continue

        udp = ip[ihl:]
        src, dst, udp_len, _ = struct.unpack("!HHHH", udp[:8])
        if dst != 51821 or udp_len < 8:
            continue

        if src != 51820:
            sys.exit(f"FAIL: unexpected UDP source port {src}")

        payload = udp[8:8 + udp_len - 8]
        if len(payload) != udp_len - 8:
            sys.exit("FAIL: truncated UDP payload")

        packets.append(payload)

expected_lengths = [13, 1452, 7, 20, 32, 148]
actual_lengths = [len(p) for p in packets]

print("UDP payload lengths:", actual_lengths)

if actual_lengths != expected_lengths:
    sys.exit(f"FAIL: expected {expected_lengths}")

prefixes = [
    bytes.fromhex("deadbeef"),
    bytes.fromhex("01020304"),
    bytes.fromhex("aabbcc"),
    bytes.fromhex("11223344"),
    bytes.fromhex("55"),
]

for index, prefix in enumerate(prefixes):
    if not packets[index].startswith(prefix):
        sys.exit(f"FAIL: I{index + 1} binary prefix")
    print(f"PASS: I{index + 1}, {len(packets[index])} bytes")

# I1: 4-byte prefix, 1 random byte, 4-byte counter, 4-byte timestamp.
if packets[0][5:9] != b"\x00" * 4:
    sys.exit("FAIL: I1 counter encoding")

# Verify timestamps from time_second (Unix seconds).
now = int(time.time())
tolerance = 30

for name, payload, offset in (
    ("I1", packets[0], 9),
    ("I3", packets[2], 3),
):
    timestamp = struct.unpack_from("!I", payload, offset)[0]
    delta = abs(now - timestamp)

    if delta > tolerance:
        sys.exit(
            f"FAIL: {name} timestamp={timestamp}, "
            f"now={now}, delta={delta}s"
        )

    print(f"PASS: {name} timestamp, delta={delta}s")

# Validate random character classes.
letters = packets[3][4:]
digits = packets[4][1:]

if not all(65 <= c <= 90 or 97 <= c <= 122 for c in letters):
    sys.exit("FAIL: I4 <rc> contains non-letter bytes")

if not all(48 <= c <= 57 for c in digits):
    sys.exit("FAIL: I5 <rd> contains non-digit bytes")

print("PASS: I4 alphabetic random data")
print("PASS: I5 numeric random data")

# Handshake initiation must follow all five junk packets.
if packets[5][:4] != b"\x01\x00\x00\x00":
    sys.exit("FAIL: handshake message type")

print("PASS: unaligned counter encoding")
print("PASS: handshake follows I1-I5")
print("ALL CHECKS PASSED")

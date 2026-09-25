#!/usr/bin/env python3
from collections import Counter


STDERR = 0x2044E0
SYSTEM = 0x58750
PAGE = 0x1000


def be_from_le32(value):
    return int.from_bytes((value & 0xFFFFFFFF).to_bytes(4, "little"), "big")


def delta_for_base(base):
    src = be_from_le32((base + STDERR) & 0xFFFFFFFF)
    dst = be_from_le32((base + SYSTEM) & 0xFFFFFFFF)
    return (dst - src) & 0xFFFFFFFF


def main():
    counts = Counter(delta_for_base(base) for base in range(0, 1 << 32, PAGE))
    total = sum(counts.values())
    covered = 0
    for delta, count in counts.most_common():
        covered += count
        print(f"0x{delta:08x} pages={count} coverage={count / total:.6f} cumulative={covered / total:.6f}")
    print(f"unique={len(counts)} total_pages={total}")


if __name__ == "__main__":
    main()

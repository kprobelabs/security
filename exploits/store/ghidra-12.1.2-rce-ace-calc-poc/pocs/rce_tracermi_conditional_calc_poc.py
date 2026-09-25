#!/usr/bin/env python3
import argparse
import os
from pathlib import Path

from calc_helper import (
    calc_command,
    calc_python_eval_expression,
    calc_shell_command,
    launch_calc,
    write_marker,
)


PATTERNS = (
    "def execute(",
    "gdb.execute(cmd",
    "exec_convert_errors(cmd",
    "def pyeval(",
    "return eval(expr)",
    "EvaluateExpression(expr)",
)


def default_source() -> Path | None:
    candidates: list[Path] = []
    env_source = os.environ.get("GHIDRA_SOURCE")
    if env_source:
        candidates.append(Path(env_source))
    candidates.extend(
        [
            Path.cwd() / "ghidra-12.1.2",
            Path(__file__).resolve().parents[2] / "ghidra-12.1.2",
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def find_hits(root: Path) -> list[tuple[Path, int, str, str]]:
    debug_root = root / "Ghidra" / "Debug"
    if not debug_root.exists():
        raise FileNotFoundError(f"Could not find Ghidra/Debug under {root}")

    hits: list[tuple[Path, int, str, str]] = []
    for method_file in debug_root.rglob("methods.py"):
        try:
            lines = method_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            for pattern in PATTERNS:
                if pattern in stripped:
                    hits.append((method_file.relative_to(root), line_no, pattern, stripped))
    return hits


def payload_shapes() -> list[str]:
    calc = calc_shell_command()

    return [
        f"GDB execute(cmd) calc-only command: shell {calc}",
        f"LLDB execute(cmd) calc-only command: platform shell {calc}",
        f"LLDB pyeval(expr) calc-only expression: {calc_python_eval_expression()}",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Conditional TraceRMI RCE calc proof-shape checker."
    )
    parser.add_argument("--ghidra-source", type=Path, default=None)
    parser.add_argument("--run-local-calc-demo", action="store_true")
    parser.add_argument("--no-calc", action="store_true")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "artifacts" / "tracermi-conditional-rce",
    )
    args = parser.parse_args()

    source = args.ghidra_source.resolve() if args.ghidra_source else default_source()
    if source is None or not source.exists():
        raise SystemExit(
            "Provide --ghidra-source or set GHIDRA_SOURCE to a Ghidra 12.1.2 source tree"
        )

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    marker = out_dir / "tracermi_local_calc_marker.txt"
    shapes_file = out_dir / "tracermi_calc_payload_shapes.txt"

    print(f"Ghidra source: {source}")
    print("Purpose: conditional TraceRMI RCE calc proof shape.")
    print("This script does not start TraceRMI, connect to an agent, or send execute requests.")

    hits = find_hits(source)
    if not hits:
        print("Result: no execution-capable TraceRMI agent method patterns were found.")
        return 2

    current_file: Path | None = None
    for relative, line_no, _pattern, text in sorted(hits):
        if current_file != relative:
            current_file = relative
            print(f"[file] {relative}")
        print(f"  [hit] line {line_no}: {text}")

    shapes = payload_shapes()
    shapes_file.write_text("\n".join(shapes) + "\n", encoding="utf-8")
    print(f"[created] {shapes_file}")

    if args.run_local_calc_demo:
        write_marker(marker, "local calc demo ran")
        print(f"[created] {marker}")
        if args.no_calc:
            print("Calc launch disabled by --no-calc.")
        else:
            if launch_calc():
                print("Local calculator launch requested.")
            else:
                print("No platform calculator command was found; marker proves execution.")
    else:
        print("Local calc demo not run. Add --run-local-calc-demo to launch calc locally.")

    print("Result: TraceRMI execution-capable agent method patterns were found.")
    print("Classification: conditional RCE, not default unauthenticated RCE.")
    print(f"Detected local calc command: {calc_command()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

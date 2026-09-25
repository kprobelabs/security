#!/usr/bin/env python3
import os
import platform
import shutil
import subprocess
from pathlib import Path


def write_marker(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


def calc_command() -> list[str] | None:
    system = platform.system().lower()
    if system == "windows":
        return ["calc.exe"]
    if system == "darwin":
        return ["open", "-a", "Calculator"]

    for name in ("xcalc", "gnome-calculator", "kcalc", "qalculate-gtk"):
        resolved = shutil.which(name)
        if resolved:
            return [resolved]
    return None


def calc_shell_command() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "calc.exe"
    if system == "darwin":
        return "open -a Calculator"
    return "xcalc || gnome-calculator || kcalc || qalculate-gtk"


def calc_python_eval_expression() -> str:
    system = platform.system().lower()
    if system == "windows":
        args = "['calc.exe']"
    elif system == "darwin":
        args = "['open', '-a', 'Calculator']"
    else:
        args = "['sh', '-lc', 'xcalc || gnome-calculator || kcalc || qalculate-gtk']"
    return f"__import__('subprocess').Popen({args})"


def launch_calc() -> bool:
    cmd = calc_command()
    if cmd is None:
        return False
    kwargs = {}
    if platform.system().lower() == "windows":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
    return True


def shell_script_header() -> str:
    if platform.system().lower() == "windows":
        return "@echo off\n"
    return "#!/bin/sh\n"


def make_executable(path: Path) -> None:
    if platform.system().lower() != "windows":
        mode = path.stat().st_mode
        path.chmod(mode | 0o111)

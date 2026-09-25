import base64


def _print_response(resp):
    print(resp.replace(b"\r\n", b"\n").decode("utf-8"))


def EHLO(p, v):
    p.sendline(f"EHLO {v}".encode("utf-8"))
    _print_response(p.recvuntil(b"HELP"))


def AUTH_PLAIN(p, v):
    p.sendline(f"AUTH PLAIN {v}".encode("utf-8"))
    _print_response(p.recvuntil(b"data"))


def UNKNOWN(p, v):
    assert isinstance(v, bytes)
    p.sendline(v)
    _print_response(p.recvuntil(b"command"))


def bad_base64(v):
    if not isinstance(v, bytes):
        v = v.encode("utf-8")
    return base64.b64encode(v).replace(b"\n", b"").replace(b"=", b"").decode("utf-8")

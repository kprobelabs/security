# Nmap IPv6 extension length wrap PoC

Compact proof of concept for an IPv6 extension-header parser length-wrap condition in Nmap's shared packet parsing code.

Research status: ongoing.

## Summary

The PoC models the IPv6 parser path in `libnetutil/netutil.cc` and the packet-length adjustment behavior in `tcpip.cc`.

A crafted IPv6 packet can declare an extension header that is only partially present in the captured packet. The parser checks that two extension-header bytes are available, uses the second byte as the extension-header length, advances the payload pointer by that declared length, and then stores the remaining payload length in an unsigned integer.

With the packet shape in this PoC:

```text
captured packet length: 48
IPv6 payload length: 8
IPv6 next header: Hop-by-Hop Options
extension next header: UDP
extension header length field: 1
```

The parser advances the payload pointer to offset 56, which is beyond the 48-byte capture, then computes the payload length as an unsigned wraparound value.

Observed local harness result:

```text
helper_returned=true
next_header=17
payload_offset=56
wrapped_payload_len=4294967288
validator_len_after_adjust=64
captured_len=48
```

That demonstrates a malformed 48-byte IPv6 packet being represented as a UDP payload beyond the packet with a very large payload length. The validation adjustment can also raise the reported captured length to 64.

## Files

- `poc/ipv6_extlen_wrap_probe.cpp` - standalone C++17 parser-behavior PoC with no source comments
- `evidence/2026-06-23-local-harness-output.txt` - local harness output
- `docs/research-inventory.md` - additional Nmap vulnerability research inventory from the same push

## Affected source path

The core parser behavior is in:

```text
libnetutil/netutil.cc:688-712
```

The validation adjustment path is in:

```text
tcpip.cc:1312-1323
```

Relevant downstream consumers include:

```text
scan_engine_raw.cc:1690-1812
scan_engine_raw.cc:1941-2008
scan_engine_raw.cc:2087-2129
```

## Build and run

Linux, macOS, WSL, or MinGW:

```bash
g++ -std=c++17 -O0 -g -Wall -Wextra -o ipv6_extlen_wrap_probe poc/ipv6_extlen_wrap_probe.cpp
./ipv6_extlen_wrap_probe
```

Windows PowerShell with MinGW:

```powershell
g++ -std=c++17 -O0 -g -Wall -Wextra -o ipv6_extlen_wrap_probe.exe .\poc\ipv6_extlen_wrap_probe.cpp
.\ipv6_extlen_wrap_probe.exe
```

Expected output:

```text
helper_returned=true
next_header=17
payload_offset=56
wrapped_payload_len=4294967288
validator_len_after_adjust=64
captured_len=48
```

## Mechanics

The helper path advances through IPv6 extension headers with this shape:

```text
p += (extension_length + 1) * 8
```

The missing invariant is a post-advance containment check before the remaining length is computed. If the declared extension length moves `p` beyond the packet end, the remaining length calculation wraps when stored in `unsigned int`.

After that, raw scan and packet validation consumers can treat the packet as if it still has a valid upper-layer payload.

## Research notes

This entry is focused on the IPv6 extension-header length wrap because it is the strongest fresh parser candidate from the latest Nmap review pass.

Other reviewed surfaces from the same research push are captured in `docs/research-inventory.md`, including raw scan short transport-header reads, Nping EchoClient NEP partial-packet handling, Ncat HTTP parser issues, and NSE negative-length behavior.

Exploitability research is ongoing around whether this parser primitive can be shaped into a stronger memory primitive beyond parser-state corruption, out-of-bounds reads, and fatal allocation behavior.

## Responsible use

Run the PoC only in a local research environment. The included PoC is a standalone arithmetic and parser-behavior harness for studying the parser transition.

# Nmap research inventory

Research status: ongoing.

This inventory captures the strongest candidates from the local Nmap review pass that produced the IPv6 extension-header length wrap PoC.

## IPv6 extension-header length wrap

Primary package candidate.

Affected path:

```text
libnetutil/netutil.cc:688-712
tcpip.cc:1312-1323
scan_engine_raw.cc:1690-1812
scan_engine_raw.cc:1941-2008
scan_engine_raw.cc:2087-2129
```

Remote IPv6 packet input can move the parser payload pointer beyond the captured packet and wrap the remaining payload length to a large unsigned value. Local harness validation shows a 48-byte packet yielding payload offset 56 and payload length `4294967288`.

Current observed behavior class:

- parser-state corruption
- out-of-bounds read paths in raw scan consumers
- fatal allocation behavior when wrapped lengths reach early UDP response storage

## Raw scan short transport-header reads

Affected path:

```text
scan_engine_raw.cc
```

Several raw scan paths copy transport headers from packet buffers after checks that allow shorter-than-copied protocol headers. The strongest cases are direct SCTP parsing, ICMP quoted-packet parsing, and encapsulated TCP/SCTP parsing. These paths are reachable from remote packet responses during raw scan modes.

Observed behavior class:

- remotely triggerable scanner crash
- out-of-bounds read from captured packet buffers
- scan-state misclassification opportunities during malformed response handling

## Nping EchoClient NEP partial-packet state

Affected path:

```text
nping/EchoClient.cc:790-864
nping/EchoClient.cc:874-940
```

The EchoClient NEP receive path retains a partial packet buffer and later combines it with new bytes based on a decrypted packet length. Suspicious state transitions include inconsistent accounting between retained bytes and new bytes, plus copies based on packet lengths derived from the encrypted stream after the user has connected to an EchoServer.

Observed behavior class:

- hostile EchoServer-triggered EchoClient crash
- negative-size and oversized-copy behavior in partial-packet transitions
- ongoing exploitability research around partial-state shaping

## Ncat HTTP proxy parser issues

Affected path:

```text
ncat/http.c
ncat/ncat_proxy.c
```

The Ncat HTTP proxy surface contains parser behaviors around embedded NUL bytes and malformed status/request lines. Existing local research reproduced loop and out-of-bounds read style behavior under malformed HTTP proxy traffic.

Observed behavior class:

- unauthenticated proxy-side denial of service
- parser desynchronization around embedded NUL handling
- status-line out-of-bounds read behavior

## Nping EchoServer stale context read

Affected path:

```text
nping/EchoServer.cc
```

EchoServer session handling has a stale-context read candidate during connection/session transition behavior. This is grouped with the Nping NEP findings because both involve Echo protocol state and attacker-controlled peer behavior.

Observed behavior class:

- server-side crash candidate
- stale session/context read during crafted peer interaction

## NSE negative-length receive behavior

Affected path:

```text
nse_nsock.cc:778-788
liblua/lapi.c:526-534
liblua/lstring.c:222-230
```

Several NSE protocol libraries compute receive lengths from remote protocol length fields. Negative script-level lengths can cross into buffered receive and Lua string construction behavior. Lua's string allocator rejects oversized string lengths before copying in the tested path.

Observed behavior class:

- script-level protocol parser failure
- allocation error path through Lua string handling
- ongoing review target for script-specific length guards

## Execution-surface survey

Reviewed code execution and code-loading surfaces include:

```text
ncat/ncat_exec_win.c
ncat/ncat_posix.c
ncat/ncat_lua.c
nselib/data/psexec/nmap_service.c
scripts/*-exec.nse
scripts/smb-psexec.nse
scripts/membase-http-info.nse
libpcap/pcap.c
```

The survey is kept in scope because the broader research goal includes execution-path discovery. The practical candidates currently remain concentrated in packet parsing and protocol state handling.

# Redis Vector Set Duplicate HNSW ID RCE PoC

This entry documents command execution through Redis Vector Set RDB loading when serialized HNSW nodes reuse the same node ID. The PoC starts an unmodified Redis binary, drives the exploit path over Redis TCP commands, and writes a marker file from code executed inside the Redis process.

## Target

| Field | Value |
| --- | --- |
| Product | Redis |
| Tested commit | `5b22a09918743ba72952e35e431db23eb3d19605` |
| Tested binary | `Redis server v=255.255.255 sha=5b22a099:0 malloc=libc bits=64 build=c8d40b9af9f5dac8` |
| Platform | Linux x86-64 |
| Allocator | libc malloc |
| Redis configuration used by the PoC | `enable-debug-command no`, `sanitize-dump-payload yes`, no persistence |
| Command surface | `RESTORE`, `VREM`, `VLINKS`, `SET`, `SETRANGE`, `DEL`, `EVAL` |

The local launcher uses the child process map and local ELF metadata to resolve the Redis PIE base, `free@GOT`, libc, and `system`. The heap corruption, read oracle, overwrite, and command execution trigger are all performed through Redis protocol commands sent to the selected stock `redis-server` process.

## Root Cause

Vector Set module deserialization accepts multiple serialized HNSW nodes that share the same node ID. During index deserialization, the ID lookup table stores only one node for each ID, while the element dictionary stores nodes by element name. Link validation then reasons about node IDs rather than enforcing a one-to-one relationship between ID and node object.

After the key is restored, removing the dictionary-visible node for a duplicated ID leaves other HNSW links pointing at the freed allocation. Those stale links remain reachable through graph operations. A quantized Vector Set turns one stale link into a stable 64-bit read oracle through `VLINKS ... WITHSCORES`. A second Vector Set uses two stale neighbors during `hnsw_reconnect_nodes()` to write attacker-selected pointers into a live module value. Deleting the corrupted key reaches `freeModuleObject()`, which dispatches through the overwritten module type pointer.

## Source Trace

| File | Relevant path |
| --- | --- |
| `modules/vector-sets/vset.c` | `hnsw_insert_serialized()` inserts restored nodes into the element dictionary before `hnsw_deserialize_index()` resolves HNSW links. |
| `modules/vector-sets/hnsw.c` | `hnsw_deserialize_index()` populates the node-ID table and validates links by ID, allowing duplicate IDs to alias distinct node objects. |
| `modules/vector-sets/hnsw.c` | `hnsw_delete_node()` calls `hnsw_reconnect_nodes()` while stale duplicate-ID neighbors are still reachable from the removed node's link array. |
| `modules/vector-sets/vset.c` | `VLINKS_RedisCommand()` exposes neighbor distances, which the PoC uses as the bit-by-bit read oracle. |
| `src/object.c` | `freeModuleObject()` calls `mv->type->free(mv->value)`, which becomes the final control-flow target after the module value overwrite. |

## Exploit Flow

1. Start the requested `redis-server` binary with a temporary configuration.
2. Use a malformed Vector Set `RESTORE` payload with duplicate HNSW IDs.
3. Remove one duplicate element with `VREM`, leaving a stale HNSW link.
4. Reclaim the freed node with a Redis string that is shaped as a fake HNSW node.
5. Use `VLINKS ... WITHSCORES` against 65 mask nodes to recover a 64-bit value from an attacker-selected address.
6. Leak `free@GOT`, derive libc, and resolve `system`.
7. Walk Redis keyspace structures with the read oracle to locate the Vector Set module value and two controlled string allocations.
8. Restore a second malformed Vector Set with two stale neighbors.
9. Reclaim both freed nodes with Redis strings shaped as fake HNSW nodes.
10. Trigger `hnsw_reconnect_nodes()` with `VREM` so the fake nodes overwrite `moduleValue->type` and `moduleValue->value`.
11. Delete the corrupted key so `freeModuleObject()` invokes `system()` with the controlled command buffer.

## Usage

Build Redis on Linux with libc malloc, then run:

```bash
python3 poc.py \
  --redis-server /path/to/redis/src/redis-server \
  --work-dir /tmp/redis-vset-rce \
  --port 6631
```

The PoC writes the marker file `R` inside the selected work directory. The marker is created by the command executed from inside the Redis process:

```text
uid=1000(owner) gid=1000(owner) groups=1000(owner),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users)
```

## Local Verification

The committed PoC was replayed from this folder against a fresh stock build:

```text
/mnt/d/exploitarium/redis-vset-duplicate-hnsw-id-rce-poc/poc.py
/mnt/d/redis-rce-validation/redis-wsl/src/redis-server
Redis server v=255.255.255 sha=5b22a099:0 malloc=libc bits=64 build=c8d40b9af9f5dac8
```

Representative output is saved in [`evidence/local-verification.txt`](evidence/local-verification.txt).

## Files

| Path | Purpose |
| --- | --- |
| [`poc.py`](poc.py) | Self-contained Redis Vector Set RCE proof. |
| [`evidence/local-verification.txt`](evidence/local-verification.txt) | Output from a successful local stock Redis replay. |

## Notes

The script is intentionally local-process oriented: it launches Redis, observes that launched process, and tears it down after the run. For long work paths, it uses a short temporary runtime directory and links `R` back to the requested work directory so the payload command can remain `id > R`. The payload produces a benign proof marker in the work directory.

Only run this against systems you own or have explicit permission to test.

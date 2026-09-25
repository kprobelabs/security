# Docker cp copy-out destination escape

This repository contains a minimal proof of concept for a `docker cp` copy-out path issue validated on Docker Engine 29.6.0.

The demonstrated behavior is:

> A process inside a running container can race a host-initiated `docker cp <container>:/tmp/src <host-destination>` operation so that the copy writes a container-controlled file into a sibling host path outside the requested destination.

The PoC uses `/tmp/.../dst` as the requested host destination and causes Docker's copy-out extraction to create `/tmp/.../dst2/marker`.

## What this is

- A host/operator-initiated `docker cp` copy-out destination escape.
- A container-controlled file write outside the requested host destination directory.
- A race against Docker's archive creation and local archive extraction behavior.
- Validated locally on Docker Client/Server 29.6.0, API 1.55, on June 23, 2026.

## What this is not

- Not a no-interaction container escape.
- Not a default runtime breakout from an idle container.
- Not a Docker socket or daemon API exposure.
- Not a kernel memory-corruption exploit.
- Not a demonstrated arbitrary host-root file write in every configuration.
- Not a claim that the PoC reaches every possible host path.

The host user who runs `docker cp` performs the extraction. The practical impact depends on who runs that command and where they copy container data.

## Preconditions

- The attacker controls files and processes inside a running Linux container.
- A host user runs `docker cp` from the attacker-controlled container to a host filesystem destination.
- The destination has a sibling path whose name has the requested destination as a raw string prefix. The PoC uses `dst` and `dst2`.
- The race wins while Docker is producing and extracting the copy-out tar stream.

The PoC widens the race by placing many padding files before the raced path.

## Reproduction

Run on a host that has Docker available:

```bash
chmod +x poc.sh
HOST_BASE=/tmp/docker-cp-copyout-repro ./poc.sh
```

Successful output includes:

```text
success=yes
requested_destination=/tmp/docker-cp-copyout-repro/dst
outside_marker_path=/tmp/docker-cp-copyout-repro/dst2/marker
outside_marker_value=container-controlled-host-marker
```

The requested destination is `.../dst`. The marker is written under the sibling `.../dst2`.

## Fresh validation

The packaged PoC was replayed successfully against Docker Client/Server 29.6.0:

```text
Client=29.6.0 Server=29.6.0 API=1.55
delay=0.010 cp_status=0 outside_marker=absent link=../../../dst2
delay=0.025 cp_status=0 outside_marker=absent link=../../../dst2
delay=0.050 cp_status=0 outside_marker=absent link=../../../dst2
delay=0.075 cp_status=0 outside_marker=absent link=../../../dst2
delay=0.100 cp_status=0 outside_marker=absent link=../../../dst2
delay=0.150 cp_status=0 outside_marker=absent link=../../../dst2
delay=0.200 cp_status=0 outside_marker=present link=../../../dst2
success=yes
requested_destination=/var/tmp/docker-cp-copyout-github/dst
outside_marker_path=/var/tmp/docker-cp-copyout-github/dst2/marker
outside_marker_value=container-controlled-host-marker
observed_symlink=/var/tmp/docker-cp-copyout-github/dst/src/dir/zzlink -> ../../../dst2
```

The validation transcript is also stored in `validation/2026-06-23-docker-29.6.0.txt`.

## Source-level notes

In Docker CLI 29.6.0, `cli/command/container/cp.go` resolves the host destination, asks the daemon for a tar stream with `CopyFromContainer`, then calls `archive.CopyTo` to extract that stream locally (`cp.go:257-338`).

On the daemon side, `daemon/archive_unix.go` creates an archive of the requested container path by opening the container filesystem and starting a `go-archive` tarballer (`archive_unix.go:40-92`). The tarballer walks the source tree with `filepath.WalkDir` and later adds the current path to the tar stream (`vendor/github.com/moby/go-archive/archive.go:693-794`). If a container process changes a directory entry after the walk has observed it but before the tar entry is added and recursed, the produced tar stream can contain a symlink at that path and then entries below the same logical path.

On the extraction side, `archive.CopyTo` prepares the destination and calls `Untar` (`vendor/github.com/moby/go-archive/copy.go:418-437`). During symlink extraction, the target is constructed with `filepath.Join(filepath.Dir(path), hdr.Linkname)` and checked with `strings.HasPrefix(targetPath, extractDir)` (`archive.go:480-490`). A path such as:

```text
extractDir=/tmp/docker-cp-copyout-repro/dst
targetPath=/tmp/docker-cp-copyout-repro/dst2
```

passes that raw prefix check even though `dst2` is outside `dst`. Later regular-file extraction opens the path normally (`archive.go:435-446`), so entries beneath the symlink are written through it into the sibling path.

Docker's container path helper also documents the general time-of-check/time-of-use caveat for scoped container paths: the returned path remains scoped only if no path component changes between resolving and using it (`daemon/container/container.go:359-363`). The PoC exercises that kind of race during copy-out archive production and combines it with the local extraction prefix issue.

## Cleanup

The PoC removes its disposable container on exit. Host output remains under `HOST_BASE` so the result can be inspected:

```bash
rm -rf /tmp/docker-cp-copyout-repro
```

## Defensive notes

Robust extraction should not rely on raw string-prefix checks for containment. A path-boundary check is better than `strings.HasPrefix`, but still does not fully address archive extraction races through symlinks. The safer design is descriptor-rooted extraction that opens path components relative to a trusted directory file descriptor and avoids following attacker-created symlinks for subsequent entries unless the target is proven to remain inside the extraction root.

Operationally, avoid running `docker cp` from containers whose contents are controlled by an untrusted party. Prefer copying from stopped containers or from immutable snapshots when the source is untrusted.

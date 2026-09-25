# Gitea act_runner `container.options` Host Namespace PoC

This repository contains a local, marker-only Python proof of concept for a Gitea `act_runner` container hardening bypass.

The issue is that workflow-controlled `jobs.<job>.container.options` is appended to Docker options for the job container. The runner forces `--privileged` back to false when the runner configuration disables privileged mode, and it sanitizes bind mounts, but it preserves other Docker flags that can be equivalent to host control on a Docker runner.

The PoC uses:

```yaml
container:
  image: ubuntu:22.04
  options: --pid=host --ipc=host --cap-add=ALL --security-opt seccomp=unconfined --security-opt apparmor=unconfined
```

The job then runs `nsenter` and writes a marker file under `/tmp` on the runner host. The default PoC disables the runner's Docker socket mount with `--container-daemon-socket=-`, so the marker demonstrates host namespace access through Docker container options rather than direct Docker socket access from the job.

## Impact

An attacker who can run a workflow on an affected Docker-backed `act_runner` can create a job container with host PID/IPC namespaces, broad Linux capabilities, and unconfined security profiles while `Privileged` remains false. In the validated environment, that allowed the workflow step to enter host namespaces and execute a host-side marker command as root.

This is high severity for repositories where untrusted users can trigger workflows on shared runners. It can be critical when a shared runner host has repository secrets, deployment credentials, adjacent jobs, or access to internal build infrastructure.

## Preconditions

- Gitea Actions is enabled.
- A Docker-backed `act_runner` executes workflows from the attacker-controlled repository or branch.
- The job image contains `nsenter`; `ubuntu:22.04` does.
- Docker accepts the preserved options shown above on the runner host.
- The runner allows workflow-authored job containers.

## Root Cause

Source-to-sink path in `act_runner`:

- `ContainerSpec.Options` accepts workflow YAML `container.options`.
- `RunContext.options()` appends workflow options to runner-level container options.
- The job container is created with `Privileged: rc.Config.Privileged`, but also with `Options: rc.options(ctx)`.
- `mergeContainerConfigs()` parses Docker CLI-style options.
- When privileged mode is disabled, only `copts.privileged` is forced false.
- The parsed HostConfig still keeps `PidMode`, `IpcMode`, `CapAdd`, `SecurityOpt`, `Devices`, `VolumesFrom`, and other non-volume fields.
- `sanitizeConfig()` only filters `Binds` and `Mounts`.

Validated dangerous HostConfig fields:

```text
Privileged=false
PidMode=host
IpcMode=host
CapAdd=["ALL"]
SecurityOpt=["seccomp=unconfined","apparmor=unconfined"]
```

## Files

- `poc.py` - stdlib-only Python PoC that generates a workflow, runs `act_runner exec`, and verifies the marker.

## Quick Start

Build or download an `act_runner` binary for the Linux host that has Docker access, then run:

```bash
python3 poc.py --runner ./act_runner --image ubuntu:22.04
```

For verbose evidence:

```bash
python3 poc.py --runner ./act_runner --image ubuntu:22.04 --debug
```

Expected success output includes:

```text
[+] verified host marker:
uid=0(root) gid=0(root) groups=0(root)
gitea-act-runner-container-options-poc-ok
```

The generated workflow is placed in a temporary directory by default. To inspect it:

```bash
python3 poc.py --runner ./act_runner --keep-workdir --debug
```

## Validation Notes

The local validation used `act_runner exec` because it exercises the same runner code path that converts workflow job container options into Docker HostConfig for a job container.

The validation command used by the PoC includes:

```bash
--container-daemon-socket=-
```

That setting prevents the normal Docker socket bind mount into the job container. The workflow still reaches the host marker through namespace entry, which isolates the issue to Docker option handling.

## Mitigation Direction

Treat workflow-authored `container.options` as untrusted input. A defensive patch should reject or allowlist job-level Docker options rather than passing the Docker CLI option surface through wholesale.

At minimum, when runner privileged mode is disabled, reject or strip:

- host namespaces: `--pid=host`, `--ipc=host`, `--uts=host`, `--cgroupns=host`, `--network=host`
- capability expansion: `--cap-add`, especially `ALL` and `SYS_ADMIN`
- security profile overrides: `--security-opt seccomp=unconfined`, `--security-opt apparmor=unconfined`, label disabling
- host device access: `--device`, `--device-cgroup-rule`, GPU/CDI device requests
- inherited volumes: `--volumes-from`
- runtime and cgroup escape-adjacent controls: `--runtime`, `--cgroup-parent`, broad sysctls

Runner operators should also avoid sharing Docker-backed runners with untrusted repositories. Use isolated, single-tenant runners or stronger sandboxing for untrusted workflows.

## Disclosure Scope

This PoC is designed for local defensive validation on infrastructure you control. It writes only a marker file and prints the verification result.

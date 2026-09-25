# Flowise 3.1.2 Custom MCP Environment Variable Case Bypass PoC

This repository documents and validates an authenticated Windows ACE/RCE-class issue in Flowise `3.1.2` / `flowise-components` `3.1.2`.

Flowise Custom MCP stdio validation blocks dangerous environment variable names such as `NODE_OPTIONS` by exact string comparison. Windows treats environment variable names case-insensitively. A casing variant such as `node_options` passes Flowise validation and is still honored by a spawned Node.js child process as `NODE_OPTIONS`.

## Affected Target

- Product: Flowise
- Version analyzed: `3.1.2`
- Package: `flowise-components@3.1.2`
- Platform impact: Windows Flowise deployments
- Required access: authenticated Flowise session or API-key context that can configure or load a Custom MCP stdio node

## Impact

An authenticated user who can reach Custom MCP stdio configuration can bypass the intended environment denylist and influence Node.js child process startup. When the MCP command is a Node.js process, a lower-case `node_options` entry can preload attacker-chosen JavaScript through Node's startup option handling.

The result is code execution in the Flowise worker/server context on Windows deployments where the Custom MCP path is reachable.

## Source Trace

Relevant source locations in Flowise `3.1.2`:

| File | Behavior |
| --- | --- |
| `packages/components/nodes/tools/MCP/CustomMCP/CustomMCP.ts` | Parses `mcpServerConfig`, validates it when `CUSTOM_MCP_SECURITY_CHECK` is enabled, and creates `MCPToolkit` with stdio when a command is present |
| `packages/components/nodes/tools/MCP/core.ts` | `MCPToolkit.createClient` passes `serverParams.env` into `StdioClientTransport` |
| `packages/components/nodes/tools/MCP/core.ts` | `validateEnvironmentVariables` denies `PATH`, `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, and `NODE_OPTIONS` by exact-case comparison |
| `@modelcontextprotocol/sdk/client/stdio.js` | The stdio transport spawns the configured process with the supplied environment |

The vulnerable validation shape is:

```ts
const dangerousEnvVars = ['PATH', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'NODE_OPTIONS']

for (const [key, value] of Object.entries(env)) {
    if (dangerousEnvVars.includes(key)) {
        throw new Error(...)
    }
}
```

On Windows, `node_options` and `NODE_OPTIONS` address the same environment variable slot for the child process, but only the exact uppercase spelling is denied.

## PoC Design

`poc.py` models the relevant Flowise validation and then launches a local Node.js process with `node_options=--require <loader>`. The loader writes a marker file. On Windows, marker creation proves that the lower-case environment variable bypasses exact-case validation and is honored by Node.js as a startup option.

The script also shows the fix shape by comparing the vulnerable exact-case validator to a normalized validator that checks `key.upper()`.

## Requirements

- Python 3.10 or newer
- Node.js available in `PATH` for the canary execution step
- Windows for full child-process behavior reproduction

## Usage

Run the PoC:

```powershell
python poc.py
```

Run with a custom marker path:

```powershell
python poc.py --marker C:\Temp\flowise_marker.txt
```

Expected Windows output shape:

```json
{
  "windows": true,
  "flowise_style_exact_upper_blocked": true,
  "flowise_style_lower_variant_accepted": true,
  "normalized_validator_blocks_lower_variant": true,
  "node_canary": {
    "canary_created": true,
    "canary_content": "node_options honored"
  },
  "finding_reproduced": true
}
```

## Exploit Preconditions

- The deployment runs on Windows.
- Custom MCP stdio support is reachable.
- The attacker has an authenticated/session/API-key path that can influence a Custom MCP node configuration.
- The configured MCP command starts a Node.js child process or another runtime with security-sensitive environment handling.

## Root Cause

The denylist comparison is platform-insensitive. Environment variable names are case-sensitive on many Unix-like systems but case-insensitive on Windows. A security check that compares environment keys by exact string spelling does not enforce the intended policy on Windows.

## Fix Direction

- Normalize environment variable names before comparison on every platform.
- Use platform-aware comparison rules when validating environment keys.
- Prefer an allowlist of safe environment variables for MCP stdio child processes.
- Add Windows-specific regression tests for case variants such as `node_options`, `Node_Options`, and `NoDe_OpTiOnS`.

## Validation Status

The issue was locally validated against `flowise-components@3.1.2`: exact uppercase `NODE_OPTIONS` was blocked, lowercase `node_options` was accepted, and the MCP stdio path created a marker file through Node.js startup option handling.

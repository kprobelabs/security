# Lunar Client Modrinth Explore Chain PoC

Proof package for a high-severity Lunar Client chain observed in the June 2026
unpacked Electron application.

This repository documents a practical RCE-style chain and includes a benign
cross-platform calc-pop proof for the final "drop local launcher and open it via
the OS shell" primitive.

## Status

High-confidence critical candidate, not yet a fully packaged public
Modrinth-to-Lunar end-to-end exploit.

The chain is severe because it joins several individually dangerous behaviors:

- Modrinth project content is rendered in Lunar Explore as raw HTML.
- The Explore renderer has access to privileged Lunar preload APIs.
- The renderer can reach raw IPC/Redux state synchronization into main.
- Main accepts forged profile state and materializes provider profiles.
- Modrinth override extraction can write root-level override files into a
  profile-controlled game directory.
- The unverified modpack warning path only scans `mods`, `resourcepacks`, and
  `shaderpacks`, not root overrides.
- `openExternalLink` can reach `shell.openExternal` for non-HTTP URLs when the
  initiator is not one of the two restricted user-input initiators.
- Opening shell-dispatched local launcher files can execute code. On Windows,
  the reviewed chain uses `.lnk`; the included proof also has macOS/Linux
  branches for environments where Windows is unavailable.

If the live Modrinth delivery leg is confirmed end-to-end through Lunar's
production cache, the likely impact is arbitrary code execution as the victim's
desktop user after the victim views or clicks a malicious Modrinth project in
Lunar Explore. This path does not require launching Minecraft, having a JRE
ready, or having a selected Minecraft account.

## Impact

Estimated severity: critical.

Tentative CVSS v3.1: `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` = 9.6.

This score assumes the attacker can publish or otherwise get attacker-controlled
Modrinth project/changelog content rendered by Lunar Explore, and that the raw
HTML delivery path executes script-capable content in the packaged renderer.

## Chain Summary

1. Attacker-controlled Modrinth Markdown is fetched by Lunar Explore.
2. Lunar renders that Markdown through `ReactMarkdown` with `rehypeRaw`, without
   an observed sanitizer or HTML allowlist.
3. A raw HTML payload can execute renderer JavaScript through an iframe-style
   delivery primitive.
4. Renderer JavaScript can use exposed preload APIs and raw IPC/Redux sync.
5. The renderer forges or creates a Modrinth provider profile whose
   `overrides.gameDirectory` points at a writable attacker-chosen directory.
6. The renderer asks main to install the forged Modrinth profile.
7. Main downloads the `.mrpack`, saves the profile, and extracts root-level
   `overrides/*` entries to `getEffectiveGameDirectory(profile)`.
8. A root override such as a benign launcher file is written to the chosen
   directory and is not covered by the unverified-file warning scanner.
9. The renderer calls the external-link API on a `file:///.../<launcher>` URL
   using a non-restricted initiator.
10. Main reaches `shell.openExternal(url)`. The operating system dispatches the
    local launcher.

## Evidence From Local Review

The following paths refer to extracted source-map sources from the reviewed
Lunar Client build.

- Raw HTML Markdown sink:
  `src/renderer/impl/app/pages/explore/project/components/markdown.tsx`
  imports `ReactMarkdown`, uses `rehypeRaw`, and does not apply a sanitizer.
- Modrinth content flow:
  `src/renderer/impl/app/pages/explore/project/utils/fetch.ts` maps project
  `body` and version `changelog` into renderer state.
- Main install handler:
  `src/electron/module/modrinth/index.ts` exposes `installModpack`.
- Profile source of truth:
  `src/electron/module/modrinth/install/modpack/index.ts` reads the target
  profile from `launcherRedux.store.getState().profiles.profiles`.
- Profile reducer:
  `src/shared/store/profiles/index.ts` accepts `profiles/addOrUpdateProfile`
  and inserts or replaces the supplied profile object.
- Profile persistence:
  `src/electron/module/profiles/index.ts` preserves `profile.overrides` when
  saving a virtual profile.
- Effective game directory:
  `src/electron/module/profiles/paths.ts` returns
  `profile.overrides.gameDirectory` when present.
- Override extraction:
  `src/electron/module/profiles/handlers/extract-overrides/utils.ts` maps
  non-content-dir `overrides/*` entries to the effective game directory.
- Warning coverage:
  `src/electron/module/profiles/handlers/unverified-modpack-files/consts.ts`
  scans only `overrides/mods/`, `overrides/resourcepacks/`, and
  `overrides/shaderpacks/`.
- External open sink:
  `src/electron/window/preload/impl/misc.ts` blocks non-HTTP protocols only for
  selected initiators, then calls `shell.openExternal(url)`.
- Redux bridge:
  `src/electron/redux/index.ts` enables `stateSyncEnhancer()` with no observed
  application-level action allowlist.

## Calc-Pop PoC

Run this only on a local test machine. It does not interact with Lunar Client or
any live Modrinth project. It validates the final execution primitive by:

1. writing a marker file,
2. creating a local platform-appropriate launcher file,
3. asking the OS shell to open that launcher, and
4. popping the Calculator app where available.

```bash
npm run poc
```

Expected output:

```text
marker: calc-pop-attempted
opened: <launcher path>
```

Platform behavior:

- Windows: creates and opens a `.lnk` pointing to `calc.exe`.
- macOS: creates and opens a `.command` launcher that runs Calculator.
- Linux: creates and opens a `.desktop` launcher for the first available
  calculator binary from a small allowlist.

In the original audit environment, the Windows shortcut primitive also wrote
`lnk-executed` to a marker file when the shortcut was opened.

## What Is Intentionally Not Included

This repository does not include:

- A live malicious Modrinth project.
- A weaponized iframe or renderer payload.
- A `.mrpack` containing an executable launcher.
- A script that drives Lunar Client against real users.

See `poc/renderer-chain-skeleton.md` for a non-executable outline of the
renderer-side chain.

## Fix Guidance

Recommended fixes should be layered:

- Disable raw HTML in Modrinth Markdown, or sanitize with a strict allowlist.
- Forbid script-capable embedded content in Explore project descriptions and
  changelogs.
- Remove generic renderer access to raw IPC `sendMessage`, or enforce a strict
  channel allowlist in preload.
- Disable or constrain Electron Redux state sync from untrusted renderers.
- Validate profile objects at every IPC/main boundary.
- Do not accept arbitrary renderer-supplied `gameDirectory` paths without a
  real user gesture and path policy.
- Treat every `overrides/*` archive entry as potentially dangerous, including
  root-level files.
- Block `file:`, `ms-*`, and other non-web protocols in `openExternalLink`
  unless there is a narrow, explicit allowlist.
- Refuse to open executable file types such as `.lnk`, `.exe`, `.bat`, `.cmd`,
  `.ps1`, `.vbs`, and similar from renderer-controlled URLs.

## Disclosure Note

This is intended for authorized validation and coordinated disclosure. Keep the
repository private until the vendor has acknowledged and remediated the issue.

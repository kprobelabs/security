# Renderer Chain Skeleton

This is a non-executable outline. It intentionally omits a working payload.

## Preconditions To Validate In A Private Lab

- A private Modrinth project or controlled API fixture can return raw HTML in
  project `body` or version `changelog`.
- Lunar Explore renders that content in the packaged launcher.
- The injected frame can access the exposed `window.lunar` or
  `window.electron` preload bridge from the rendered context.
- The main Redux bridge accepts a forged `profiles/addOrUpdateProfile` action.
- `installModpack` accepts the forged profile ID.
- Override extraction writes root `overrides/*` files to the controlled
  effective game directory.
- `openExternalLink` reaches `shell.openExternal` for a local launcher file URL
  with a non-restricted initiator.

## Non-Executable Flow

1. Build a virtual profile object with these properties:
   - `id`: fresh local ID
   - `type`: `modrinth`
   - `provider`: `modrinth`
   - `state`: `virtual`
   - `useLunarFeatures`: compatible with target Modrinth version
   - `modrinth.projectId`: controlled test project
   - `modrinth.selectedVersion.versionId`: controlled test version
   - `overrides.gameDirectory`: writable test directory
2. Send a profile-add action into the main Redux state-sync channel.
3. Invoke the Lunar Modrinth install API for that profile ID.
4. Confirm the controlled test `.mrpack` root override is written under the
   chosen game directory.
5. Invoke the Lunar external-link API with a local `file:` URL to the benign
   launcher file.
6. Confirm the calculator pop or marker file.

## Expected Benign Result

The validation succeeds only if a benign calculator pop or marker file is
observed. Do not test with an arbitrary command or payload outside a controlled
lab.

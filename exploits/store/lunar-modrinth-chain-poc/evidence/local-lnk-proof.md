# Local Launcher Proof

Observed during local validation:

```text
Directory: work\lnk-proof

marker.txt
payload.lnk
lnk-executed
```

Interpretation:

- A local `.lnk` was created with a harmless marker target.
- Opening the shortcut caused Windows to execute the target.
- The marker file contained `lnk-executed`.

This validates the final operating-system primitive used by the proposed Lunar
chain. It does not prove the complete Lunar end-to-end exploit by itself.

The repository now includes `poc/calc-pop.js`, a Node.js proof that performs a
visible calculator pop using a local launcher file:

- Windows: `.lnk` to `calc.exe`
- macOS: `.command` running `open -a Calculator`
- Linux: `.desktop` launcher for an installed calculator binary

Observed output from the replacement PoC on Windows:

```text
> lunar-modrinth-chain-poc@0.1.0 poc
> node poc/calc-pop.js

marker: calc-pop-attempted
opened: ...\poc\poc-output\calc-pop.lnk
```

# ImageMagick Ghostscript Delegate Search Path PoC

This repository contains a Python proof of concept for a Windows executable search-path issue in ImageMagick's Ghostscript delegate handling.

When ImageMagick converts PDF, PS, EPS, or related PostScript-family inputs on Windows, it builds a Ghostscript delegate command. In the fallback path where ImageMagick does not have a full Ghostscript executable path, the delegate command uses the bare executable name `gswin64c.exe`. The command is then launched through the Windows process API with the application name left unset, which allows normal Windows executable search behavior to choose the program that gets launched.

If the converter process runs from a directory that an attacker can write to, a planted `gswin64c.exe` in that directory can be launched when ImageMagick processes a PDF/PS-family file.

## Tested Versions

The local verification used:

- ImageMagick `7.1.2-25`
- Ghostscript `10.07.1`
- Windows x64
- Python 3

The PoC uses a harmless marker-writing helper named `gswin64c.exe`. The helper only writes a text file showing that it was launched and records the delegate arguments that ImageMagick passed.

## Repository Layout

- `poc.py`: Python replay harness.
- `helper/FakeGswin64c.cs`: source code for the marker-writing helper payload.
- `helper/gswin64c.exe.b64`: base64-encoded helper executable generated from `helper/FakeGswin64c.cs`.

## How The Bug Works

ImageMagick's delegate configuration contains Ghostscript command templates that reference `@PSDelegate@`. On Windows, that placeholder is filled by code that tries to locate Ghostscript. When a full path is available, the command points to that full path. In the fallback path, ImageMagick substitutes `gswin64c.exe`.

The resulting command has this shape:

```text
"gswin64c.exe" -q -dQUIET -dSAFER -dBATCH -dNOPAUSE ... "-sDEVICE=pngalpha" ...
```

Because the executable is a bare name, Windows resolves it through process search rules. A copy of `gswin64c.exe` in the current working directory can be selected before the real Ghostscript binary from `PATH`.

The PoC creates two directories:

- `control`: contains only a benign PDF. ImageMagick resolves `gswin64c.exe` from `PATH`, and conversion succeeds.
- `hijack`: contains the same benign PDF plus a marker-writing `gswin64c.exe`. ImageMagick launches the marker helper from the working directory.

For deterministic lab reproduction, the PoC points `MAGICK_GHOSTSCRIPT_PATH` at a throwaway directory that does not contain Ghostscript DLLs. That forces ImageMagick through the same fallback branch used by portable/no-registry deployments where a full Ghostscript path is unavailable.

## Requirements

- Windows
- Python 3
- ImageMagick for Windows with PDF/PS delegate support
- Ghostscript for Windows

The PoC accepts explicit paths, so it works with portable builds as well as installed builds.

## Usage

With `magick.exe` and `gswin64c.exe` already in `PATH`:

```bash
python poc.py
```

With explicit paths:

```bash
python poc.py \
  --magick "C:\path\to\magick.exe" \
  --gs-bin "C:\path\to\ghostscript\bin"
```

For portable ImageMagick builds that need a config directory:

```bash
python poc.py \
  --magick "C:\path\to\ImageMagick\magick.exe" \
  --magick-configure-path "C:\path\to\ImageMagick" \
  --gs-bin "C:\path\to\ghostscript\bin"
```

The script prints JSON evidence and writes a `result.json` file into the generated evidence directory.

Successful output includes:

```json
{
  "control": {
    "output_exists": true
  },
  "hijack": {
    "marker_exists": true,
    "marker_text": "fake gswin64c executed\n..."
  }
}
```

The marker text contains the exact delegate arguments passed by ImageMagick.

## Reproduction Flow

1. Create a benign PDF input.
2. Create a control directory with only that PDF.
3. Create a second directory with the same PDF and a marker helper named `gswin64c.exe`.
4. Prepend the real Ghostscript `bin` directory to `PATH`.
5. Run ImageMagick from the control directory and verify normal rendering.
6. Run ImageMagick from the second directory and verify that the local `gswin64c.exe` wrote the marker.

## Mitigations

Operational mitigations:

- Configure ImageMagick so Ghostscript resolves to an absolute executable path.
- Set `MAGICK_GHOSTSCRIPT_PATH` to the real Ghostscript `bin` directory when using ImageMagick in automated conversion services.
- Run conversion jobs from a trusted working directory that untrusted users cannot write to.
- Keep upload directories, extraction directories, and conversion working directories separate.
- Disable PDF/PS-family delegate processing when those formats are not required.

Code-level hardening:

- Avoid launching delegate programs by bare executable name.
- Pass an explicit absolute executable path to the process creation API.
- Set the child process working directory to a trusted location.
- Reject delegate execution when the resolved executable path is relative.

## Notes

The helper payload in `helper/gswin64c.exe.b64` is generated from `helper/FakeGswin64c.cs`. It writes only the marker file named by `IM_GS_MARKER` and returns.

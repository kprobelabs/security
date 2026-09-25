# 7-Zip RAR5 MotW/ADS Full-Chain PoC

This repository contains a self-contained Python proof-of-concept for a RAR5 alternate-stream handling issue in 7-Zip 26.01 on Windows.

The crafted RAR5 archive contains one visible file entry and two RAR5 `STM` service records:

- `invoice.docx::$DATA` changes the final visible bytes of the extracted file.
- `invoice.docx:Zone.Identifier:$DATA` changes the extracted file's Mark-of-the-Web stream.

When the source archive has an Internet-zone `Zone.Identifier`, 7-Zip propagates that marker to the extracted file. The crafted stream name with a `:$DATA` suffix then writes to the same NTFS stream name as Windows resolves it on disk. The result is an extracted `invoice.docx` whose visible content and MotW stream are both controlled by archive data.

## Tested Target

- 7-Zip 26.01 x64 for Windows
- Windows NTFS destination
- Python 3.10+

## Run

Use an installed 7-Zip:

```powershell
python .\poc.py --sevenzip "C:\Program Files\7-Zip\7z.exe"
```

Or pass any 7-Zip 26.01 `7z.exe` path:

```powershell
python .\poc.py --sevenzip "C:\path\to\7z.exe" --work-dir .\poc-run
```

Expected successful output:

```text
[+] 7-Zip: 7-Zip 26.01 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-04-27
[+] archive sha256: A962DDB7A0313545521C3250EB7E01EB275F50C83DBC0466FFC94011FB4A0800
[+] final visible content: ATTACKER final visible bytes from ::$DATA stream\r\n
[+] final Zone.Identifier: [ZoneTransfer]\r\nZoneId=0\r\n
[+] VULNERABLE: full chain verified
```

## What The PoC Verifies

The script performs the full chain:

1. Builds a minimal RAR5 archive in Python.
2. Adds a normal `invoice.docx` file entry with benign-looking bytes.
3. Adds a RAR5 `STM` stream named `::$DATA` with attacker-controlled final file bytes.
4. Adds a RAR5 `STM` stream named `:Zone.Identifier:$DATA` with attacker-controlled MotW bytes.
5. Marks the source archive itself as Internet-zone with `ZoneId=3`.
6. Extracts with 7-Zip using zone propagation.
7. Checks that the extracted `invoice.docx` contains the `::$DATA` payload.
8. Checks that `invoice.docx:Zone.Identifier` contains `ZoneId=0`.

## Why It Works

7-Zip has special handling for `Zone.Identifier` propagation. It recognizes and suppresses an exact archive-provided `Zone.Identifier` alternate stream while applying the source archive's Internet-zone marker to the extracted file.

The crafted stream name uses a Windows stream type suffix:

```text
Zone.Identifier:$DATA
```

7-Zip's guard treats that as a different stream name, but NTFS resolves:

```text
file:Zone.Identifier
file:Zone.Identifier:$DATA
```

to the same alternate data stream. The archive-provided stream therefore replaces the propagated marker.

The same stream suffix behavior is used with:

```text
::$DATA
```

which targets the unnamed/default NTFS data stream of the extracted file. That is why the final visible file bytes differ from the benign main file entry.

## Files Written

The PoC writes only inside the selected work directory:

- `rar5-content-and-motw-chain.rar`
- `out\invoice.docx`
- NTFS alternate streams attached to those files

The default work directory is `.\poc-run`.


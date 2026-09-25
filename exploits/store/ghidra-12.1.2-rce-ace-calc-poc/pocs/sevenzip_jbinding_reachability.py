#!/usr/bin/env python3
import argparse
import os
import zipfile
from pathlib import Path


CHECKS = (
    ("SevenZipJBinding dependency", "Ghidra/Features/FileFormats/build.gradle", "sevenzipjbinding:16.02-2.01"),
    ("SevenZip all-platforms dependency", "Ghidra/Features/FileFormats/build.gradle", "sevenzipjbinding-all-platforms:16.02-2.01"),
    (
        "Archive probe path",
        "Ghidra/Features/FileFormats/src/main/java/ghidra/file/formats/sevenzip/SevenZipFileSystemFactory.java",
        "probeStartBytes",
    ),
    (
        "SevenZip file system mount",
        "Ghidra/Features/FileFormats/src/main/java/ghidra/file/formats/sevenzip/SevenZipFileSystemFactory.java",
        "new SevenZipFileSystem",
    ),
    (
        "Native archive open",
        "Ghidra/Features/FileFormats/src/main/java/ghidra/file/formats/sevenzip/SevenZipFileSystem.java",
        "SevenZip.openInArchive",
    ),
    (
        "Native library load",
        "Ghidra/Features/FileFormats/src/main/java/ghidra/file/formats/sevenzip/SevenZipCustomInitializer.java",
        "System.load",
    ),
    (
        "ZIP tries SevenZip path",
        "Ghidra/Features/FileFormats/src/main/java/ghidra/file/formats/zip/ZipFileSystemFactory.java",
        "SevenZipFileSystemFactory.initNativeLibraries",
    ),
)


def default_source() -> Path | None:
    candidates: list[Path] = []
    env_source = os.environ.get("GHIDRA_SOURCE")
    if env_source:
        candidates.append(Path(env_source))
    candidates.extend(
        [
            Path.cwd() / "ghidra-12.1.2",
            Path(__file__).resolve().parents[2] / "ghidra-12.1.2",
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Benign SevenZipJBinding reachability checker.")
    parser.add_argument("--ghidra-source", type=Path, default=None)
    parser.add_argument("--create-harmless-zip", action="store_true")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "artifacts",
    )
    args = parser.parse_args()

    source = args.ghidra_source.resolve() if args.ghidra_source else default_source()
    if source is None or not source.exists():
        raise SystemExit(
            "Provide --ghidra-source or set GHIDRA_SOURCE to a Ghidra 12.1.2 source tree"
        )

    print(f"Ghidra source: {source}")
    print("Purpose: benign reachability check only. No exploit archive or command payload is generated.")

    failed = False
    for name, rel_path, pattern in CHECKS:
        path = source / rel_path
        if not path.exists():
            print(f"[missing] {name}: {rel_path}")
            failed = True
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if pattern in text:
            line_no = text[: text.index(pattern)].count("\n") + 1
            print(f"[found]   {name}: {rel_path}:{line_no}")
        else:
            print(f"[miss]    {name}: {rel_path}")
            failed = True

    if args.create_harmless_zip:
        out_dir = args.out_dir.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        zip_path = out_dir / "harmless-sevenzip-sample.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("hello.txt", "harmless sample for parser reachability checks\n")
        print(f"[created] harmless ZIP sample: {zip_path}")

    if failed:
        print("Result: one or more expected reachability checks were not found.")
        return 2

    print("Result: expected SevenZipJBinding reachability evidence was found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

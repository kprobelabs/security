# Source Evidence Summary

## Swift Demangler ACE

- `SwiftDemanglerAnalyzer.java` restores a Swift binary directory analyzer
  option.
- `SwiftNativeDemangler.java` builds the native demangler path from the
  configured Swift directory.
- `SwiftNativeDemangler.java` executes the native demangler with `--version`.
- `SwiftNativeDemangler.java` executes the native demangler during symbol
  demangling.

## TraceRMI Conditional RCE

- GDB agent `methods.py` exposes `execute(cmd)`.
- The GDB implementation calls `gdb.execute(cmd, to_string=...)`.
- LLDB agent `methods.py` exposes `execute(cmd)`.
- The LLDB implementation routes the command string to the LLDB command
  interpreter.
- LLDB agent `methods.py` exposes `pyeval(expr)`.
- The LLDB implementation calls Python `eval(expr)`.

These are execution-capable sinks once a TraceRMI agent channel is exposed or
connected to an untrusted controller.

## SevenZipJBinding Reachability

- `Ghidra/Features/FileFormats/build.gradle` declares
  `sevenzipjbinding:16.02-2.01`.
- `Ghidra/Features/FileFormats/build.gradle` declares
  `sevenzipjbinding-all-platforms:16.02-2.01`.
- `SevenZipFileSystemFactory.probeStartBytes(...)` recognizes archive
  signatures.
- `SevenZipFileSystemFactory.create(...)` constructs `SevenZipFileSystem`.
- `SevenZipFileSystem.mount(...)` calls `SevenZip.openInArchive(...)`.
- `SevenZipCustomInitializer.initSevenZip()` loads native libraries with
  `System.load(...)`.
- `ZipFileSystemFactory.create(...)` tries the SevenZip path for ZIP handling
  unless built-in ZIP handling is forced.


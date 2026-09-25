# Ghidra 12.1.2 Conditional ACE/RCE Calc PoCs

This repository packages the closest verified code-execution conditions found
while reviewing Ghidra 12.1.2.

It is deliberately precise about the classification:

- **ACE calc PoC:** conditional Swift demangler path execution. This is local
  arbitrary code execution when a restored/configured Swift tool directory is
  used by the Swift demangler analyzer.
- **RCE calc PoC shape:** conditional TraceRMI debugger-agent command execution.
  This is real code execution when an untrusted peer can drive an already
  created TraceRMI debugger-agent channel.
- **Default-reachable RCE-class surface:** SevenZipJBinding native archive
  parsing. This is source reachability evidence for a native parser surface.

## Repository Contents

- `pocs/ace_swift_demangler_calc_poc.py`  
  Creates a fake `swift-demangle` tool and, when run, simulates the Ghidra
  Swift demangler process-launch sink by writing a marker and optionally
  launching the local platform calculator.

- `pocs/rce_tracermi_conditional_calc_poc.py`  
  Checks a Ghidra source tree for TraceRMI execution-capable agent methods and
  emits calc-only command shapes for those sinks. It can also launch local
  calculator as a benign proof marker for local validation.

- `pocs/sevenzip_jbinding_reachability.py`  
  Source reachability checker for the SevenZipJBinding native archive parser
  path.

- `pocs/SevenZipReachabilityProbe.java`  
  Optional benign runtime probe that opens a harmless ZIP through
  SevenZipJBinding when the caller supplies the dependency jars.

- `evidence/source-evidence.md`  
  Short source-to-sink evidence for the three reviewed surfaces.

- `docs/classification.md`  
  Finding classification and why the claims are conditional.

## Quick Start

The PoCs are standard-library Python scripts. Use whichever launcher exists on
your system: `python3`, `python`, or `py -3`.

Pass a source checkout explicitly:

```bash
python3 pocs/rce_tracermi_conditional_calc_poc.py --ghidra-source /path/to/ghidra-12.1.2
```

Or set `GHIDRA_SOURCE`:

```bash
export GHIDRA_SOURCE=/path/to/ghidra-12.1.2
python3 pocs/sevenzip_jbinding_reachability.py
```

Run the ACE calc simulator in dry-run mode:

```bash
python3 pocs/ace_swift_demangler_calc_poc.py
```

Run the ACE calc simulator and launch the platform calculator:

```bash
python3 pocs/ace_swift_demangler_calc_poc.py --run
```

Run marker-only mode:

```bash
python3 pocs/ace_swift_demangler_calc_poc.py --run --no-calc
```

Check the TraceRMI conditional RCE sinks in a local Ghidra source checkout:

```bash
python3 pocs/rce_tracermi_conditional_calc_poc.py --ghidra-source /path/to/ghidra-12.1.2
```

Emit calc-only TraceRMI command shapes and launch local calculator as a proof
marker:

```bash
python3 pocs/rce_tracermi_conditional_calc_poc.py \
  --ghidra-source /path/to/ghidra-12.1.2 \
  --run-local-calc-demo
```

Run SevenZipJBinding source reachability checks:

```bash
python3 pocs/sevenzip_jbinding_reachability.py --ghidra-source /path/to/ghidra-12.1.2
```

## ACE: Swift Demangler Path

The Swift demangler path is a conditional arbitrary-code-execution condition.
The relevant source-to-sink shape is:

1. Program/analyzer state can influence the Swift binary directory.
2. The Swift native demangler builds a path under that directory.
3. The demangler validation and symbol demangling paths launch the configured
   `swift-demangle` executable.

The PoC script creates a local fake Swift tool directory and invokes the fake
demangler directly, matching the process-launch shape. This proves the
calc-capable sink for the configured Swift demangler condition.

## RCE: TraceRMI Agent Channel

TraceRMI is classified as conditional RCE because the debugger agent methods
include command/eval sinks exposed through a TraceRMI control channel. Examples
seen in Ghidra 12.1.2 source include:

- GDB agent: `execute(cmd)` calls `gdb.execute(cmd, ...)`.
- LLDB agent: `execute(cmd)` routes to the LLDB command interpreter.
- LLDB agent: `pyeval(expr)` calls Python `eval(expr)`.

Once an untrusted peer can drive such an exposed agent channel, the impact is
code execution in the debugger-agent context. The exposure precondition is an
agent channel reachable by an untrusted controller or peer.

The RCE script records calc-only command shapes and can launch local calc to
demonstrate the sink impact. Use it for defensive reproduction planning and
patch/hardening discussion.

## SevenZipJBinding Native Parser Exposure

Ghidra 12.1.2 includes SevenZipJBinding 16.02-era native code and routes
recognized archive bytes into that parser in-process. This is a serious
RCE-class parser exposure because reverse engineers routinely open untrusted
archives and firmware containers.

The included checks prove reachability with benign source checks and harmless
archive sample generation.

## Portability Notes

The scripts accept source paths from `--ghidra-source`, `GHIDRA_SOURCE`, or a
nearby `ghidra-12.1.2` directory. Calculator launch is best effort:

- Windows: `calc.exe`
- macOS: `open -a Calculator`
- Linux: `xcalc`, `gnome-calculator`, `kcalc`, or `qalculate-gtk`

## Expected Output

The PoC scripts write markers under `artifacts/` by default:

- `artifacts/swift-demangler-calc/swift_demangler_calc_marker.txt`
- `artifacts/tracermi-conditional-rce/tracermi_local_calc_marker.txt`
- `artifacts/tracermi-conditional-rce/tracermi_calc_payload_shapes.txt`

The `artifacts/` directory is ignored by Git.

## Responsible Use

Use this repository for defensive validation, reproduction notes, and hardening
discussion with the stated preconditions.

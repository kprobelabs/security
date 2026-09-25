# Classification

## Closest Verified ACE

**Swift demangler analyzer path, conditional.**

The execution sink is a native process launch of a configured Swift demangler
tool. The condition is that analysis reaches the Swift demangler path and the
Swift tool directory resolves to attacker-controlled executable content.

This is ACE because the execution is local to the Ghidra user context and does
not require a remote channel.

## Closest Verified RCE

**TraceRMI debugger-agent channel, conditional.**

The execution sinks are debugger-agent methods that call debugger command
interpreters or Python evaluation paths. The condition is that an untrusted peer
can drive an already created TraceRMI control channel, or can cause an agent to
connect to an untrusted controller.

This is RCE in that condition because the command originates across a
debugger/IPC boundary and executes in the debugger-agent context.

## Closest Default-Reachable RCE-Class Surface

**SevenZipJBinding native parser exposure, not verified code execution.**

Archive bytes can reach native 7-Zip parsing code inside the Ghidra JVM. That
is an RCE-class parser surface, but this repository does not claim a
Ghidra-specific calc exploit for it.


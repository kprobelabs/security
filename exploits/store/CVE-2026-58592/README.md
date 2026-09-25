# Ladybird WebAssembly ESM Host Function RCE PoC

This folder contains a standalone browser page that drives a WebAssembly lifetime bug into native code execution in Ladybird's WebContent process.

The PoC combines two browser-reachable primitives:

- a WebAssembly ESM host-function type lifetime bug that lets a stale Wasm register be consumed as an abstract Wasm GC array reference;
- an `ImageData` and WebGL readback leak from a moved memory64 backing store that recovers heap and library pointers needed to stabilize the native write path.

The marker command is:

```sh
touch /tmp/ladybird_wasm_esm_rce
```

## Files

| File | Purpose |
| --- | --- |
| `poc.html` | Standalone HTML exploit page. |
| `README.md` | Reproduction notes, source trace, and exploit design. |

## Tested Target

The PoC was developed against upstream Ladybird commit:

```text
31bb4d872d802c78ce23d2f273a300f36e8ef6a0
```

The replay target is the normal `ladybird` browser binary in headless mode. The page has no dependency on `test-web`, layout-test includes, `internals`, or source patches.

The native offsets in `poc.html` match the tested Linux build:

| Component | Offset |
| --- | ---: |
| `Wasm::ArrayInstance` vtable in `liblagom-wasm.so.0.1.0` | `0x59ba60` |
| `__cxa_finalize@GLOB_DAT` in `liblagom-wasm.so.0.1.0` | `0x59d300` |
| `__cxa_finalize` in libc | `0x472c0` |
| `setcontext` in libc | `0x4a960` |
| `system` in libc | `0x58750` |
| `exit` in libc | `0x47ba0` |
| `pop rdi; ret` in libc | `0x10f78b` |

## Run

Build Ladybird from the tested commit, then run the page with the browser binary:

```sh
rm -f /tmp/ladybird_wasm_esm_rce
Build/gui-sanitizers/bin/ladybird --headless=screenshot --screenshot-delay=20 --screenshot-path=/tmp/ladybird-wasm-esm.png file:///absolute/path/to/poc.html
ls -l /tmp/ladybird_wasm_esm_rce
```

Successful replay creates `/tmp/ladybird_wasm_esm_rce`. The browser process may terminate after the marker is created because the final trigger redirects a native virtual call through a crafted context.

## Root Cause

`Libraries/LibWeb/WebAssembly/WebAssembly.cpp` creates JS host callbacks with a `Wasm::FunctionType const& type` parameter:

```text
WebAssembly.cpp:239
Wasm::HostFunction create_host_function(JS::VM& vm, JS::FunctionObject& function, Wasm::FunctionType const& type, ByteString const& name)

WebAssembly.cpp:242
[&](auto&, auto arguments) -> Wasm::Result {
```

The returned host callback captures by reference and uses `type.parameters()` and `type.results()` later, after the caller has returned.

The ESM import path in `Libraries/LibWeb/WebAssembly/WebAssemblyModule.cpp` constructs the function type as a stack local before passing it into `create_host_function`:

```text
WebAssemblyModule.cpp:336
auto functype = entry.description().visit(...)

WebAssemblyModule.cpp:358
auto host_function = Detail::create_host_function(vm, function, functype, ...)
```

That gives the long-lived host function a dangling reference to a stack `FunctionType`.

`Libraries/LibWasm/AbstractMachine/BytecodeInterpreter.cpp` then accepts the dynamic result vector returned by the host function without enforcing that it matches the static function type at the call site:

```text
BytecodeInterpreter.cpp:6760
if (!result.values().is_empty()) {
    configuration.push_to_destination(...)
}
```

When stale `type.results()` data makes the host function return an empty `Vector<Wasm::Value>` for a statically non-empty result, the destination register keeps its previous value.

Wasm GC array operations consume abstract references by trusting the low pointer bits after only a null-reference check:

```text
BytecodeInterpreter.cpp:6112
GC_TRAP_IF(is_null_gc_reference(reference), "null array reference");

BytecodeInterpreter.cpp:6113
auto& instance = *static_cast<ArrayInstance*>(bit_cast<GC::Cell*>(reference.value().low()));

BytecodeInterpreter.cpp:6116
instance.elements()[index] = pack_into_field(field_type.type(), value);
```

The PoC seeds the stale destination register with a controlled abstract reference shape, then routes `array.set` into attacker-chosen native memory.

## Leak Primitive

The address-discovery stage uses an existing browser-reachable memory64 and canvas lifetime issue.

`Libraries/LibWeb/HTML/ImageData.cpp` wraps the backing storage of a `Uint8ClampedArray` directly:

```text
ImageData.cpp:24
Gfx::Bitmap::create_wrapper(..., data.data().data())
```

`Libraries/LibGfx/Bitmap.cpp` stores that pointer in a non-owning bitmap wrapper:

```text
Bitmap.cpp:116
Bitmap::create_wrapper(..., void* data, ...)
```

For memory64, `LibWasm` uses the fallback `ByteBuffer` path rather than the fixed wasm32 reservation. Growing the memory can move the backing store while the `ImageData` bitmap still points at the old address. The PoC fills that old region with predictable JS objects and Wasm GC objects, then uses `WebGL2RenderingContext.texImage2D` and `readPixels` to recover pointer-shaped values.

Those leaks recover:

- `ArrayBuffer` object addresses;
- backing-store addresses;
- a `Wasm::ArrayInstance` address;
- the `liblagom-wasm` base from the `ArrayInstance` vtable;
- the libc base through `__cxa_finalize@GLOB_DAT`.

## Exploit Path

The final chain is:

1. Import a JavaScript function into a WebAssembly ESM module with static result type `arrayref`.
2. Trigger the dangling `FunctionType` reference in the host callback.
3. Make the host callback dynamically return zero Wasm values.
4. Preserve a stale register that contains an attacker-shaped abstract GC reference.
5. Use Wasm GC `array.set` to write through a fake `ArrayInstance`.
6. Retarget a `DataView` backing store to obtain native read and write.
7. Resolve `liblagom-wasm` and libc bases from leaked pointers.
8. Craft a fake virtual dispatch target and `setcontext` frame.
9. Trigger a WebGL virtual call and execute the marker command.

## Fix Direction

The host function callback should own the canonical `FunctionType` it uses after creation, or capture a stable copy instead of a reference to caller-owned storage.

The Wasm interpreter should also validate host result arity against the callee's static result type before returning to bytecode execution. A call that expects one result should trap or throw if the host function returns zero values, and it should clear or overwrite the destination register on every path.

For the leak stage, `ImageData` should avoid caching raw pointers into user-supplied typed-array backing stores whose address can change. Re-deriving the backing pointer and byte length at use time would remove the stale bitmap pointer.

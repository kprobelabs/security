#!/usr/bin/env pythoimport argparse
import struct
from pathlib import Path


EM_DLX = 0x5AA5
R_DLX_PCREL26 = 9
R_DLX_RELOC_32 = 3
MASK26 = 0x03FFFFFF


def p16(v):
    return struct.pack(">H", v & 0xFFFF)


def p32(v):
    return struct.pack(">I", v & 0xFFFFFFFF)


def strtab(strings):
    blob = b"\x00"
    offsets = {"": 0}
    for s in strings:
        if s and s not in offsets:
            offsets[s] = len(blob)
            blob += s.encode("ascii") + b"\x00"
    return blob, offsets


def sym(name, value, size, info, shndx):
    return p32(name) + p32(value) + p32(size) + bytes([info, 0]) + p16(shndx)


def build_elf(debug_size, relocs):
    di = b"\x00" * debug_size
    tx = b"\x00" * 4
    sec_names = [
        ".text",
        ".debug_info",
        ".rel.debug_info",
        ".symtab",
        ".strtab",
        ".shstrtab",
    ]
    shstr, shoff = strtab(sec_names)
    names = [f"s{i}" for i in range(len(relocs))]
    str_blob, stroff = strtab(names)

    symtab = b""
    symtab += sym(0, 0, 0, 0, 0)
    symtab += sym(0, 0, 0, 0x03, 1)
    symtab += sym(0, 0, 0, 0x03, 2)
    for i, reloc in enumerate(relocs):
        _offset, value = reloc[:2]
        symtab += sym(stroff[f"s{i}"], value, 4, 0x12, 2)

    rb = b""
    for i, reloc in enumerate(relocs):
        offset, _value = reloc[:2]
        r_type = reloc[2] if len(reloc) > 2 else R_DLX_PCREL26
        r_info = ((3 + i) << 8) | r_type
        rb += p32(offset) + p32(r_info)

    o = 52
    text_off = o
    o += len(tx)
    debug_off = o
    o += len(di)
    rel_off = o
    o += len(rb)
    sym_off = o
    o += len(symtab)
    str_off = o
    o += len(str_blob)
    shstr_off = o
    o += len(shstr)
    shdr_off = o

    def shdr(name, stype, flags, offset, size, link, info, align, entsize):
        return (
            p32(name)
            + p32(stype)
            + p32(flags)
            + p32(0)
            + p32(offset)
            + p32(size)
            + p32(link)
            + p32(info)
            + p32(align)
            + p32(entsize)
        )

    hdrs = b""
    hdrs += shdr(0, 0, 0, 0, 0, 0, 0, 0, 0)
    hdrs += shdr(shoff[".text"], 1, 6, text_off, len(tx), 0, 0, 4, 0)
    hdrs += shdr(shoff[".debug_info"], 1, 0, debug_off, len(di), 0, 0, 1, 0)
    hdrs += shdr(shoff[".rel.debug_info"], 9, 0x40, rel_off, len(rb), 4, 2, 4, 8)
    hdrs += shdr(shoff[".symtab"], 2, 0, sym_off, len(symtab), 5, 3, 4, 16)
    hdrs += shdr(shoff[".strtab"], 3, 0, str_off, len(str_blob), 0, 0, 1, 0)
    hdrs += shdr(shoff[".shstrtab"], 3, 0, shstr_off, len(shstr), 0, 0, 1, 0)

    ident = b"\x7fELF" + bytes([1, 2, 1, 0]) + b"\x00" * 8
    ehdr = (
        ident
        + p16(1)
        + p16(EM_DLX)
        + p32(1)
        + p32(0)
        + p32(0)
        + p32(shdr_off)
        + p32(0)
        + p16(52)
        + p16(0)
        + p16(0)
        + p16(40)
        + p16(7)
        + p16(6)
    )
    return ehdr + tx + di + rb + symtab + str_blob + shstr + hdrs


def decode_dlx_vallo(low26):
    low26 &= MASK26
    if low26 & 0x03000000:
        return (~(low26 | 0xFC000000) + 1) & 0xFFFFFFFF
    return low26


def low26_to_signed(low26):
    low26 &= MASK26
    if low26 & 0x02000000:
        return low26 - 0x04000000
    return low26


def word_to_low26(word):
    return word & MASK26


def symbol_for_low26(current_word, final_low26):
    final_low26 &= MASK26
    signed_final = low26_to_signed(final_low26)
    if signed_final == -0x02000000:
        raise ValueError("DLX PCREL26 cannot encode final low26 0x02000000")
    vallo = decode_dlx_vallo(word_to_low26(current_word))
    return (vallo + signed_final) & 0xFFFFFFFF


def encodable_low26(final_low26):
    return (final_low26 & MASK26) != 0x02000000


def apply_dlx_word(memory, offset, symbol_value):
    cur = int.from_bytes(bytes(memory[offset : offset + 4]), "big")
    vallo = decode_dlx_vallo(cur & MASK26)
    val = ((symbol_value & 0xFFFFFFFF) - vallo) & 0xFFFFFFFF
    if val & 0x80000000:
        val_signed = val - 0x100000000
    else:
        val_signed = val
    if abs(val_signed) > 0x01FFFFFF:
        raise ValueError(f"relocation would be out of range: {val_signed:#x}")
    new_word = (cur & 0xFC000000) | (val_signed & MASK26)
    memory[offset : offset + 4] = new_word.to_bytes(4, "big")


class ChainBuilder:
    def __init__(self, debug_size, rbase, memory_base, memory):
        self.debug_size = debug_size
        self.rbase = rbase
        self.memory_base = memory_base
        self.memory = bytearray(memory)
        self.relocs = []
        self.notes = []
        self._initialized_addresses = set()

    def _mem_index(self, target):
        idx = target - self.memory_base
        if idx < 0 or idx + 4 > len(self.memory):
            raise ValueError(f"target {target:#x} outside modeled memory")
        return idx

    def _raw_reloc(self, offset, symbol_value, note):
        idx = len(self.relocs)
        self.relocs.append((offset & 0xFFFFFFFF, symbol_value & 0xFFFFFFFF))
        self.notes.append((idx, offset, symbol_value & 0xFFFFFFFF, note))
        self._set_address_field(idx, offset & 0xFFFFFFFF)
        return idx

    def add_pi32_reloc(self, target, delta, note):
        actual_idx = len(self.relocs) + (2 if target < 0 else 0)
        self._set_address_field(actual_idx, target & 0xFFFFFFFF)
        if target < 0:
            self._patch_negative_address_for_index(actual_idx)
        idx = len(self.relocs)
        self.relocs.append((target & 0xFFFFFFFF, delta & 0xFFFFFFFF, R_DLX_RELOC_32))
        self.notes.append((idx, target, delta & 0xFFFFFFFF, note))
        self._set_address_field(idx, target & 0xFFFFFFFF)
        mem_idx = self._mem_index(target)
        cur = int.from_bytes(bytes(self.memory[mem_idx : mem_idx + 4]), "big")
        new = (cur + (delta & 0xFFFFFFFF)) & 0xFFFFFFFF
        self.memory[mem_idx : mem_idx + 4] = new.to_bytes(4, "big")

    def _set_address_field(self, reloc_idx, address):
        if reloc_idx in self._initialized_addresses:
            return
        field = self.rbase + reloc_idx * 32 + 8
        mem_idx = field - self.memory_base
        if 0 <= mem_idx and mem_idx + 8 <= len(self.memory):
            self.memory[mem_idx : mem_idx + 8] = (address & 0xFFFFFFFF).to_bytes(8, "little")
            self._initialized_addresses.add(reloc_idx)

    def _positive_write_low26(self, target, final_low26, note):
        idx = self._mem_index(target)
        cur = int.from_bytes(bytes(self.memory[idx : idx + 4]), "big")
        symv = symbol_for_low26(cur, final_low26)
        self._raw_reloc(target, symv, note)
        apply_dlx_word(self.memory, idx, symv)

    def _patch_negative_address_for_index(self, actual_idx):
        h = self.rbase + actual_idx * 32 + 12
        self._positive_write_low26(h - 1, 0x03FFFFFF, f"patch reloc{actual_idx} address high dword bytes 0..2")
        self._positive_write_low26(h, 0x03FFFFFF, f"patch reloc{actual_idx} address high dword byte 3")

    def write_low26(self, target, final_low26, note):
        if target < 0:
            actual_idx = len(self.relocs) + 2
            self._set_address_field(actual_idx, target & 0xFFFFFFFF)
            self._patch_negative_address_for_index(actual_idx)
            self._raw_reloc(target & 0xFFFFFFFF, 0, f"{note} placeholder before simulation")
            idx = self._mem_index(target)
            cur = int.from_bytes(bytes(self.memory[idx : idx + 4]), "big")
            symv = symbol_for_low26(cur, final_low26)
            self.relocs[-1] = (target & 0xFFFFFFFF, symv)
            self.notes[-1] = (actual_idx, target, symv, note)
            apply_dlx_word(self.memory, idx, symv)
        else:
            self._positive_write_low26(target, final_low26, note)

    def write_bytes4(self, target, data):
        if len(data) != 4:
            raise ValueError("write_bytes4 needs exactly 4 bytes")
        prior_idx = self._mem_index(target - 1)
        prior_low2 = self.memory[prior_idx] & 3
        low_a = (
            (prior_low2 << 24)
            | (data[0] << 16)
            | (data[1] << 8)
            | data[2]
        )
        low_b = ((data[0] & 3) << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
        if encodable_low26(low_a) and encodable_low26(low_b):
            self.write_low26(target - 1, low_a, f"stage write bytes at {target:#x}")
            self.write_low26(target, low_b, f"finish write bytes at {target:#x}")
            return

        tail_idx = self._mem_index(target + 2)
        tail_low2 = self.memory[tail_idx] & 3
        for filler in range(0x10000):
            low_tail = (tail_low2 << 24) | (data[3] << 16) | filler
            if encodable_low26(low_tail) and encodable_low26(low_a):
                self.write_low26(target + 2, low_tail, f"fallback tail byte for {target:#x}")
                self.write_low26(target - 1, low_a, f"fallback first three bytes at {target:#x}")
                return
        raise ValueError(f"no DLX byte decomposition for target {target:#x}")


def parse_hex_bytes(value):
    value = value.replace(" ", "").replace(":", "")
    if len(value) % 2:
        raise argparse.ArgumentTypeError("hex byte string must have an even length")
    return bytes.fromhex(value)


def parse_write(spec):
    off, data = spec.split(":", 1)
    return int(off, 0), parse_hex_bytes(data)


def parse_patch(spec):
    off, data = spec.split(":", 1)
    return int(off, 0), parse_hex_bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug-size", type=int, default=144)
    parser.add_argument("--rbase", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--memory-base", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--memory-hex", type=parse_hex_bytes)
    parser.add_argument("--memory-size", type=lambda x: int(x, 0))
    parser.add_argument("--patch-mem", action="append", type=parse_patch, default=[])
    parser.add_argument("--write4", action="append", type=parse_write, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--notes", type=Path)
    args = parser.parse_args()

    if args.memory_hex is None:
        if args.memory_size is None:
            parser.error("either --memory-hex or --memory-size is required")
        memory = bytearray(args.memory_size)
    else:
        memory = bytearray(args.memory_hex)
        if args.memory_size is not None and args.memory_size > len(memory):
            memory.extend(b"\x00" * (args.memory_size - len(memory)))

    for off, data in args.patch_mem:
        idx = off - args.memory_base
        if idx < 0 or idx + len(data) > len(memory):
            parser.error(f"--patch-mem offset {off:#x} outside modeled memory")
        memory[idx : idx + len(data)] = data

    builder = ChainBuilder(args.debug_size, args.rbase, args.memory_base, memory)
    for target, data in args.write4:
        builder.write_bytes4(target, data)

    args.out.write_bytes(build_elf(args.debug_size, builder.relocs))
    print(args.out.resolve())
    print(f"relocations={len(builder.relocs)}")
    if args.notes:
        lines = []
        for idx, target, symv, note in builder.notes:
            lines.append(f"{idx:03d} target={target:#x} sym=0x{symv:08x} {note}")
        args.notes.write_text("\n".join(lines) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""TNT deobfuscator for Mach-O x86_64 and arm64 binaries.

It supports:
- thin Mach-O 64-bit (x86_64, arm64)
- fat Mach-O (32/64 fat headers), patching selected supported slices
- static mode (XOR metadata deobfuscation)
- dynamic mode (Unicorn emulation and memory dump)
"""

from __future__ import annotations

import argparse
import dataclasses
import struct
import sys
from pathlib import Path
from typing import Iterable


CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
SUPPORTED_CPU_TYPES = {
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM64: "arm64",
}

MH_MAGIC_64_BYTES_LE = b"\xcf\xfa\xed\xfe"
MH_MAGIC_64_BYTES_BE = b"\xfe\xed\xfa\xcf"

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

MACH_HEADER_64_SIZE = 32
MAX_TABLE_SCAN = 2 * 1024 * 1024
MAX_TABLE_DWORDS = 16384

# Load commands.
LC_SEGMENT_64 = 0x19
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB

# Section types / attributes.
SECTION_TYPE = 0x000000FF
S_REGULAR = 0x0
S_CSTRING_LITERALS = 0x2
S_LAZY_SYMBOL_POINTERS = 0x7
S_SYMBOL_STUBS = 0x8
S_MOD_INIT_FUNC_POINTERS = 0x9
SECTION_ATTRIBUTES = 0xFFFFFF00
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

# Mach VM protections.
VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2
VM_PROT_EXECUTE = 0x4

# Indirect symbol table sentinels.
INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000

# Dyld bind opcodes.
BIND_OPCODE_MASK = 0xF0
BIND_IMMEDIATE_MASK = 0x0F
BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
BIND_OPCODE_SET_TYPE_IMM = 0x50
BIND_OPCODE_SET_ADDEND_SLEB = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB = 0x80
BIND_OPCODE_DO_BIND = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0

MACH_NLIST_64_SIZE = 16
POINTER_SIZE_64 = 8
PAGE_SIZE = 0x1000

CODE_ADDRESS = 0x0
STACK_ADDRESS_X64 = 0xBFF00000
STACK_ADDRESS_ARM64 = 0x70000000
STACK_SIZE = 10 * 1024 * 1024

DEFAULT_DYNAMIC_TIMEOUT_MS = 30000
DEFAULT_DYNAMIC_MAX_INSN = 2000000

VERBOSE = False


class DeobfuscationError(Exception):
    pass


def _vlog(message: str) -> None:
    if VERBOSE:
        print(f"[VERBOSE] {message}", file=sys.stderr)


@dataclasses.dataclass(frozen=True)
class MachOHeader64:
    endian: str
    cputype: int
    cpusubtype: int
    filetype: int
    ncmds: int
    sizeofcmds: int
    flags: int
    reserved: int


@dataclasses.dataclass(frozen=True)
class SliceInfo:
    arch: str
    cputype: int
    offset: int
    size: int
    source: str


@dataclasses.dataclass(frozen=True)
class TableCandidate:
    table_offset: int
    table_end: int
    obfuscated_count: int
    xor_key: int
    entries: list[int]


@dataclasses.dataclass(frozen=True)
class SliceResult:
    arch: str
    source: str
    slice_offset: int
    slice_size: int
    xor_key: int
    pair_count: int
    patched_bytes: int
    table_offset: int
    fixed_symbol_strings: int
    fixed_section_names: int


@dataclasses.dataclass(frozen=True)
class DynamicSliceResult:
    arch: str
    source: str
    slice_offset: int
    slice_size: int
    load_method: int
    mprotect_stub: int | None
    dyld_get_slide_stub: int | None
    fixed_symbol_strings: int
    fixed_section_names: int
    write_min: int | None
    write_max: int | None
    emu_status: str


@dataclasses.dataclass(frozen=True)
class SegmentInfo:
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int


@dataclasses.dataclass(frozen=True)
class SectionInfo:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int
    flags: int
    align: int
    reserved1: int
    reserved2: int
    header_offset: int
    seg_maxprot: int
    seg_initprot: int


@dataclasses.dataclass(frozen=True)
class ParsedSliceMeta:
    segments: list[SegmentInfo]
    sections: list[SectionInfo]
    stubs_sections: list[SectionInfo]
    lazy_symbol_sections: list[SectionInfo]
    objc_const_section: SectionInfo | None
    objc_data_section: SectionInfo | None
    lazy_bind_off: int | None
    lazy_bind_size: int
    symoff: int | None
    nsyms: int
    stroff: int | None
    strsize: int
    indirectsymoff: int | None
    nindirectsyms: int


def _cpu_to_arch(cputype: int) -> str | None:
    return SUPPORTED_CPU_TYPES.get(cputype)


def _parse_macho_header_64(blob: memoryview) -> MachOHeader64:
    if len(blob) < MACH_HEADER_64_SIZE:
        raise DeobfuscationError("buffer too small for mach_header_64")

    magic = bytes(blob[:4])
    if magic == MH_MAGIC_64_BYTES_LE:
        endian = "<"
    elif magic == MH_MAGIC_64_BYTES_BE:
        endian = ">"
    else:
        raise DeobfuscationError("not a 64-bit Mach-O slice")

    unpacked = struct.unpack_from(f"{endian}IiiIIIII", blob, 0)
    _, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = unpacked

    return MachOHeader64(
        endian=endian,
        cputype=cputype,
        cpusubtype=cpusubtype,
        filetype=filetype,
        ncmds=ncmds,
        sizeofcmds=sizeofcmds,
        flags=flags,
        reserved=reserved,
    )


def _decode_uleb128(blob: memoryview, pos: int, end: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < end:
        byte = blob[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return value, pos
        shift += 7
        if shift > 63:
            raise DeobfuscationError("uleb128 overflow")
    raise DeobfuscationError("truncated uleb128")


def _decode_sleb128(blob: memoryview, pos: int, end: int) -> tuple[int, int]:
    value = 0
    shift = 0
    byte = 0
    while pos < end:
        byte = blob[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if (byte & 0x80) == 0:
            break
    else:
        raise DeobfuscationError("truncated sleb128")

    if shift < 64 and (byte & 0x40):
        value |= -(1 << shift)
    return value, pos


def _read_c_string(blob: memoryview, pos: int, end: int) -> tuple[str, int]:
    cur = pos
    while cur < end and blob[cur] != 0:
        cur += 1
    if cur >= end:
        raise DeobfuscationError("unterminated string in dyld bind opcodes")
    raw = bytes(blob[pos:cur])
    return raw.decode("utf-8", "replace"), cur + 1


def _parse_slice_meta(slice_blob: memoryview, header: MachOHeader64) -> ParsedSliceMeta:
    endian = header.endian

    cmd_off = MACH_HEADER_64_SIZE
    cmds_end = cmd_off + header.sizeofcmds
    if cmds_end > len(slice_blob):
        raise DeobfuscationError("invalid mach_header_64 sizeofcmds")

    segments: list[SegmentInfo] = []
    sections: list[SectionInfo] = []
    stubs_sections: list[SectionInfo] = []
    lazy_symbol_sections: list[SectionInfo] = []
    objc_const_section: SectionInfo | None = None
    objc_data_section: SectionInfo | None = None

    lazy_bind_off: int | None = None
    lazy_bind_size = 0
    symoff: int | None = None
    nsyms = 0
    stroff: int | None = None
    strsize = 0
    indirectsymoff: int | None = None
    nindirectsyms = 0

    for _ in range(header.ncmds):
        if cmd_off + 8 > cmds_end:
            raise DeobfuscationError("truncated load command")
        cmd, cmdsize = struct.unpack_from(f"{endian}II", slice_blob, cmd_off)
        if cmdsize < 8 or cmd_off + cmdsize > cmds_end:
            raise DeobfuscationError("invalid load command size")

        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise DeobfuscationError("invalid LC_SEGMENT_64 command size")
            (
                _cmd,
                _cmdsize,
                _segname,
                vmaddr,
                _vmsize,
                fileoff,
                filesize,
                maxprot,
                initprot,
                nsects,
                _flags,
            ) = struct.unpack_from(f"{endian}II16sQQQQiiII", slice_blob, cmd_off)

            # Basic file-range sanity check for segment payload.
            if filesize > 0 and (fileoff >= len(slice_blob) or fileoff + filesize > len(slice_blob)):
                raise DeobfuscationError("segment file range exceeds slice bounds")

            segments.append(
                SegmentInfo(
                    vmaddr=vmaddr,
                    vmsize=_vmsize,
                    fileoff=fileoff,
                    filesize=filesize,
                    maxprot=maxprot,
                    initprot=initprot,
                )
            )

            section_base = cmd_off + 72
            required_size = section_base + nsects * 80
            if required_size > cmd_off + cmdsize:
                raise DeobfuscationError("invalid section list in LC_SEGMENT_64")

            for i in range(nsects):
                s_off = section_base + i * 80
                (
                    raw_sectname,
                    raw_segname2,
                    addr,
                    size,
                    file_offset,
                    align,
                    _reloff,
                    _nreloc,
                    flags,
                    reserved1,
                    reserved2,
                    _reserved3,
                ) = struct.unpack_from(f"{endian}16s16sQQIIIIIIII", slice_blob, s_off)
                sectname = raw_sectname.split(b"\x00", 1)[0].decode("ascii", "ignore")
                segname = raw_segname2.split(b"\x00", 1)[0].decode("ascii", "ignore")

                section = SectionInfo(
                    sectname=sectname,
                    segname=segname,
                    addr=addr,
                    size=size,
                    offset=file_offset,
                    flags=flags,
                    align=align,
                    reserved1=reserved1,
                    reserved2=reserved2,
                    header_offset=s_off,
                    seg_maxprot=maxprot,
                    seg_initprot=initprot,
                )
                sections.append(section)
                if (flags & SECTION_TYPE) == S_SYMBOL_STUBS:
                    stubs_sections.append(section)
                if (flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS:
                    lazy_symbol_sections.append(section)
                if sectname == "__objc_const":
                    objc_const_section = section
                elif sectname == "__objc_data":
                    objc_data_section = section

        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            if cmdsize < 48:
                raise DeobfuscationError("invalid LC_DYLD_INFO[_ONLY] size")
            fields = struct.unpack_from(f"{endian}12I", slice_blob, cmd_off)
            lazy_bind_off = fields[8]
            lazy_bind_size = fields[9]

        elif cmd == LC_SYMTAB:
            if cmdsize < 24:
                raise DeobfuscationError("invalid LC_SYMTAB size")
            _cmd, _cmdsize, symoff, nsyms, stroff, strsize = struct.unpack_from(
                f"{endian}6I", slice_blob, cmd_off
            )

        elif cmd == LC_DYSYMTAB:
            if cmdsize < 80:
                raise DeobfuscationError("invalid LC_DYSYMTAB size")
            fields = struct.unpack_from(f"{endian}20I", slice_blob, cmd_off)
            indirectsymoff = fields[14]
            nindirectsyms = fields[15]

        cmd_off += cmdsize

    return ParsedSliceMeta(
        segments=segments,
        sections=sections,
        stubs_sections=stubs_sections,
        lazy_symbol_sections=lazy_symbol_sections,
        objc_const_section=objc_const_section,
        objc_data_section=objc_data_section,
        lazy_bind_off=lazy_bind_off,
        lazy_bind_size=lazy_bind_size,
        symoff=symoff,
        nsyms=nsyms,
        stroff=stroff,
        strsize=strsize,
        indirectsymoff=indirectsymoff,
        nindirectsyms=nindirectsyms,
    )


def _parse_lazy_bind_symbol_map(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
) -> dict[int, str]:
    if meta.lazy_bind_off is None or meta.lazy_bind_size <= 0:
        return {}
    if not meta.segments:
        return {}

    bind_start = meta.lazy_bind_off
    bind_end = bind_start + meta.lazy_bind_size
    if bind_end > len(slice_blob):
        raise DeobfuscationError("lazy bind opcodes exceed slice bounds")

    cur_symbol: str | None = None
    seg_index: int | None = None
    seg_offset = 0
    addr_map: dict[int, str] = {}
    pos = bind_start

    def do_bind() -> None:
        nonlocal seg_offset
        if cur_symbol is None or seg_index is None:
            return
        if seg_index >= len(meta.segments):
            return
        slot_addr = meta.segments[seg_index].vmaddr + seg_offset
        addr_map[slot_addr] = cur_symbol

    while pos < bind_end:
        byte = slice_blob[pos]
        pos += 1
        opcode = byte & BIND_OPCODE_MASK
        imm = byte & BIND_IMMEDIATE_MASK

        if opcode == BIND_OPCODE_DONE:
            # lazy bind streams can contain multiple entries separated by DONE.
            # Continue scanning until lazy_bind_size is exhausted.
            cur_symbol = None
            seg_index = None
            seg_offset = 0
            continue
        if opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            continue
        if opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            _value, pos = _decode_uleb128(slice_blob, pos, bind_end)
            continue
        if opcode == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            continue
        if opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            cur_symbol, pos = _read_c_string(slice_blob, pos, bind_end)
            continue
        if opcode == BIND_OPCODE_SET_TYPE_IMM:
            continue
        if opcode == BIND_OPCODE_SET_ADDEND_SLEB:
            _value, pos = _decode_sleb128(slice_blob, pos, bind_end)
            continue
        if opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_index = imm
            seg_offset, pos = _decode_uleb128(slice_blob, pos, bind_end)
            continue
        if opcode == BIND_OPCODE_ADD_ADDR_ULEB:
            value, pos = _decode_uleb128(slice_blob, pos, bind_end)
            seg_offset += value
            continue
        if opcode == BIND_OPCODE_DO_BIND:
            do_bind()
            seg_offset += POINTER_SIZE_64
            continue
        if opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            do_bind()
            value, pos = _decode_uleb128(slice_blob, pos, bind_end)
            seg_offset += POINTER_SIZE_64 + value
            continue
        if opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            do_bind()
            seg_offset += POINTER_SIZE_64 + (imm * POINTER_SIZE_64)
            continue
        if opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count, pos = _decode_uleb128(slice_blob, pos, bind_end)
            skip, pos = _decode_uleb128(slice_blob, pos, bind_end)
            for _ in range(count):
                do_bind()
                seg_offset += POINTER_SIZE_64 + skip
            continue

        raise DeobfuscationError(f"unsupported bind opcode 0x{opcode:02x}")

    return addr_map


def _write_name16(slice_blob: memoryview, offset: int, name: str) -> int:
    if offset + 16 > len(slice_blob):
        return 0
    data = name.encode("ascii", "ignore")[:16]
    data = data + (b"\x00" * (16 - len(data)))
    current = bytes(slice_blob[offset : offset + 16])
    if current == data:
        return 0
    slice_blob[offset : offset + 16] = data
    return 1


def _restore_section_names(slice_blob: memoryview, meta: ParsedSliceMeta) -> int:
    changed = 0
    cstring_idx = 0

    for section in meta.sections:
        sect_type = section.flags & SECTION_TYPE

        is_exec = bool(section.seg_maxprot & VM_PROT_EXECUTE) and bool(
            section.seg_initprot & VM_PROT_EXECUTE
        )
        is_rw_data = (
            section.seg_maxprot == (VM_PROT_READ | VM_PROT_WRITE)
            and section.seg_initprot == (VM_PROT_READ | VM_PROT_WRITE)
        )

        if is_exec:
            changed += _write_name16(slice_blob, section.header_offset + 16, "__TEXT")
            if sect_type == S_SYMBOL_STUBS:
                changed += _write_name16(slice_blob, section.header_offset, "__stubs")
            elif sect_type == S_CSTRING_LITERALS:
                changed += _write_name16(
                    slice_blob, section.header_offset, f"__cstring{cstring_idx}"
                )
                cstring_idx += 1
            elif sect_type == S_REGULAR:
                attrs = section.flags & SECTION_ATTRIBUTES
                if (attrs & S_ATTR_PURE_INSTRUCTIONS) and (attrs & S_ATTR_SOME_INSTRUCTIONS):
                    if section.align == 2:
                        changed += _write_name16(slice_blob, section.header_offset, "__stub_helper")
                    elif section.align == 4:
                        changed += _write_name16(slice_blob, section.header_offset, "__text")

        if is_rw_data:
            changed += _write_name16(slice_blob, section.header_offset + 16, "__DATA")
            if sect_type == S_LAZY_SYMBOL_POINTERS:
                changed += _write_name16(slice_blob, section.header_offset, "__la_symbol_ptr")
            elif sect_type == S_MOD_INIT_FUNC_POINTERS:
                changed += _write_name16(slice_blob, section.header_offset, "__mod_init_func")

    return changed


def _restore_symbol_strings(
    slice_blob: memoryview,
    header: MachOHeader64,
    meta: ParsedSliceMeta,
) -> int:
    if (
        meta.symoff is None
        or meta.stroff is None
        or meta.indirectsymoff is None
        or meta.nsyms <= 0
        or meta.nindirectsyms <= 0
        or meta.strsize <= 0
    ):
        return 0

    symtab_end = meta.symoff + meta.nsyms * MACH_NLIST_64_SIZE
    strtab_end = meta.stroff + meta.strsize
    indirect_end = meta.indirectsymoff + meta.nindirectsyms * 4
    if symtab_end > len(slice_blob) or strtab_end > len(slice_blob) or indirect_end > len(slice_blob):
        return 0

    try:
        ptr_to_name = _parse_lazy_bind_symbol_map(slice_blob, meta)
    except DeobfuscationError as exc:
        print(f"[WARN] symbol restore skipped: {exc}", file=sys.stderr)
        return 0
    if not ptr_to_name:
        return 0

    fixed = 0
    written_offsets: set[int] = set()
    endian = header.endian

    for section in meta.lazy_symbol_sections:
        if section.size < POINTER_SIZE_64:
            continue

        entry_count = section.size // POINTER_SIZE_64
        for i in range(entry_count):
            indirect_index = section.reserved1 + i
            if indirect_index >= meta.nindirectsyms:
                break

            (symbol_index,) = struct.unpack_from(
                f"{endian}I",
                slice_blob,
                meta.indirectsymoff + indirect_index * 4,
            )
            if symbol_index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS):
                continue
            if symbol_index >= meta.nsyms:
                continue

            ptr_addr = section.addr + i * POINTER_SIZE_64
            name = ptr_to_name.get(ptr_addr)
            if not name:
                continue

            nlist_off = meta.symoff + symbol_index * MACH_NLIST_64_SIZE
            (strx,) = struct.unpack_from(f"{endian}I", slice_blob, nlist_off)
            if strx >= meta.strsize:
                continue
            string_off = meta.stroff + strx
            if string_off in written_offsets:
                continue

            cur_end = string_off
            while cur_end < strtab_end and slice_blob[cur_end] != 0:
                cur_end += 1
            if cur_end >= strtab_end:
                continue

            old_len = cur_end - string_off
            new_bytes = name.encode("utf-8", "replace")
            # Keep replacement safe: don't overwrite neighboring strings.
            if len(new_bytes) > old_len:
                continue

            slice_blob[string_off : string_off + len(new_bytes)] = new_bytes
            for p in range(string_off + len(new_bytes), cur_end):
                slice_blob[p] = 0
            fixed += 1
            written_offsets.add(string_off)

    return fixed


def _align_up(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


def _read_u32(slice_blob: memoryview, offset: int, endian: str) -> int:
    if offset < 0 or offset + 4 > len(slice_blob):
        raise DeobfuscationError("out-of-bounds u32 read")
    return struct.unpack_from(f"{endian}I", slice_blob, offset)[0]


def _read_u64(slice_blob: memoryview, offset: int, endian: str) -> int:
    if offset < 0 or offset + 8 > len(slice_blob):
        raise DeobfuscationError("out-of-bounds u64 read")
    return struct.unpack_from(f"{endian}Q", slice_blob, offset)[0]


def _locate_objc_load_method(
    slice_blob: memoryview,
    header: MachOHeader64,
    meta: ParsedSliceMeta,
    xor_key_hint: int | None = None,
) -> int:
    def xor_u64(value: int) -> int:
        if xor_key_hint is None:
            return value
        mask = int.from_bytes(bytes([xor_key_hint]) * 8, "little")
        return value ^ mask

    def select_in_range(raw_value: int, start: int, end: int) -> int:
        if start <= raw_value < end:
            return raw_value
        if xor_key_hint is not None:
            alt = xor_u64(raw_value)
            if start <= alt < end:
                return alt
        raise DeobfuscationError("pointer outside expected range")

    exec_ranges = [
        (seg.vmaddr, seg.vmaddr + seg.vmsize)
        for seg in meta.segments
        if (seg.maxprot & VM_PROT_EXECUTE) and seg.vmsize > 0
    ]

    def select_exec_addr(raw_value: int) -> int:
        candidates = [raw_value]
        if xor_key_hint is not None:
            candidates.append(xor_u64(raw_value))
        for cand in candidates:
            for start, end in exec_ranges:
                if start <= cand < end:
                    return cand
        raise DeobfuscationError("method implementation pointer is not executable")

    objc_const = meta.objc_const_section
    objc_data = meta.objc_data_section
    if objc_const is None or objc_data is None:
        raise DeobfuscationError("missing __objc_const/__objc_data sections for dynamic mode")

    # struct __objc2_class: isa, superclass, cache, vtable, info (5 pointers)
    class_info_ptr_raw = _read_u64(slice_blob, objc_data.offset + 32, header.endian)
    class_info_ptr = select_in_range(
        class_info_ptr_raw,
        objc_const.addr,
        objc_const.addr + objc_const.size,
    )
    if class_info_ptr == 0:
        raise DeobfuscationError("Objective-C class info pointer is null")

    info_off = class_info_ptr - objc_const.addr
    if info_off < 0:
        raise DeobfuscationError("invalid Objective-C class info pointer")
    info_file_off = objc_const.offset + info_off

    # struct __objc2_class_ro: base_meths pointer at +0x20
    base_meths_ptr_raw = _read_u64(slice_blob, info_file_off + 0x20, header.endian)
    base_meths_ptr = select_in_range(
        base_meths_ptr_raw,
        objc_const.addr,
        objc_const.addr + objc_const.size,
    )
    if base_meths_ptr == 0:
        raise DeobfuscationError("Objective-C base methods pointer is null")
    meths_off = base_meths_ptr - objc_const.addr
    if meths_off < 0:
        raise DeobfuscationError("invalid Objective-C methods pointer")
    meths_file_off = objc_const.offset + meths_off

    # struct __objc2_meth_list { uint32 entrysize; uint32 count; }
    meth_count = _read_u32(slice_blob, meths_file_off + 4, header.endian)
    if meth_count < 1:
        raise DeobfuscationError("Objective-C methods list is empty")

    # struct __objc2_meth { char *name; char *types; IMP imp; }
    first_method_off = meths_file_off + 8
    load_method_raw = _read_u64(slice_blob, first_method_off + 16, header.endian)
    load_method = select_exec_addr(load_method_raw)
    if load_method == 0:
        raise DeobfuscationError("Objective-C load method pointer is null")
    return load_method


def _locate_mod_init_entry(
    slice_blob: memoryview,
    header: MachOHeader64,
    meta: ParsedSliceMeta,
    xor_key_hint: int | None = None,
) -> int:
    exec_ranges = [
        (seg.vmaddr, seg.vmaddr + seg.vmsize)
        for seg in meta.segments
        if (seg.maxprot & VM_PROT_EXECUTE) and seg.vmsize > 0
    ]
    if not exec_ranges:
        raise DeobfuscationError("no executable segment for __mod_init_func fallback")

    mod_init_sections = [sec for sec in meta.sections if (sec.flags & SECTION_TYPE) == S_MOD_INIT_FUNC_POINTERS]
    if not mod_init_sections:
        raise DeobfuscationError("missing __mod_init_func section")

    def is_exec_addr(addr: int) -> bool:
        for start, end in exec_ranges:
            if start <= addr < end:
                return True
        return False

    mask = int.from_bytes(bytes([xor_key_hint]) * 8, "little") if xor_key_hint is not None else 0
    for section in mod_init_sections:
        if section.offset < 0 or section.offset + section.size > len(slice_blob):
            continue
        count = section.size // 8
        for i in range(count):
            ptr_off = section.offset + i * 8
            raw = _read_u64(slice_blob, ptr_off, header.endian)
            if raw != 0 and is_exec_addr(raw):
                return raw
            if xor_key_hint is not None:
                alt = raw ^ mask
                if alt != 0 and is_exec_addr(alt):
                    return alt

    raise DeobfuscationError("no valid executable pointer in __mod_init_func")


def _sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


def _decode_x86_stub_target_ptr(
    slice_blob: memoryview,
    stub_file_off: int,
    stub_addr: int,
    xor_key_hint: int | None = None,
) -> int | None:
    if stub_file_off < 0 or stub_file_off + 6 > len(slice_blob):
        return None

    raw = bytes(slice_blob[stub_file_off : stub_file_off + 6])

    def decode(buf: bytes) -> int | None:
        if len(buf) != 6:
            return None
        if buf[0] != 0xFF or buf[1] != 0x25:
            return None
        disp = struct.unpack_from("<i", buf, 2)[0]
        return (stub_addr + 6 + disp) & 0xFFFFFFFFFFFFFFFF

    result = decode(raw)
    if result is not None:
        return result
    if xor_key_hint is None:
        return None
    deobf = bytes(b ^ xor_key_hint for b in raw)
    return decode(deobf)


def _decode_arm64_stub_target_ptr(
    slice_blob: memoryview,
    stub_file_off: int,
    stub_addr: int,
    xor_key_hint: int | None = None,
) -> int | None:
    if stub_file_off < 0 or stub_file_off + 12 > len(slice_blob):
        return None

    words = struct.unpack_from("<III", slice_blob, stub_file_off)

    def decode(insn_1: int, insn_2: int, insn_3: int) -> int | None:
        # ADRP Xd, imm
        if (insn_1 & 0x9F000000) != 0x90000000:
            return None
        reg_d = insn_1 & 0x1F
        imm_lo = (insn_1 >> 29) & 0x3
        imm_hi = (insn_1 >> 5) & 0x7FFFF
        imm_21 = _sign_extend((imm_hi << 2) | imm_lo, 21)
        page_addr = (stub_addr & ~0xFFF) + (imm_21 << 12)

        # LDR Xt, [Xn, #imm12]
        if (insn_2 & 0xFFC00000) != 0xF9400000:
            return None
        reg_t = insn_2 & 0x1F
        reg_n = (insn_2 >> 5) & 0x1F
        imm_12 = (insn_2 >> 10) & 0xFFF
        if reg_t != reg_d or reg_n != reg_d:
            return None

        # BR Xn
        if (insn_3 & 0xFFFFFC1F) != 0xD61F0000:
            return None
        reg_br = (insn_3 >> 5) & 0x1F
        if reg_br != reg_d:
            return None

        return (page_addr + (imm_12 * 8)) & 0xFFFFFFFFFFFFFFFF

    result = decode(*words)
    if result is not None:
        return result
    if xor_key_hint is None:
        return None

    key_mask = int.from_bytes(bytes([xor_key_hint]) * 4, "little")
    deobf_words = tuple(w ^ key_mask for w in words)
    return decode(*deobf_words)


def _locate_required_stubs(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
    ptr_to_name: dict[int, str],
    arch: str,
    xor_key_hint: int | None = None,
) -> tuple[int | None, int | None]:
    if not meta.stubs_sections:
        raise DeobfuscationError("missing __stubs section for dynamic mode")

    mprotect_stub: int | None = None
    dyld_stub: int | None = None

    for stubs in meta.stubs_sections:
        stub_size = stubs.reserved2
        if stub_size <= 0:
            stub_size = 6 if arch == "x86_64" else 12
        if stubs.size < stub_size:
            continue

        stub_count = stubs.size // stub_size
        for i in range(stub_count):
            stub_addr = stubs.addr + (i * stub_size)
            stub_file_off = stubs.offset + (i * stub_size)

            if arch == "x86_64":
                ptr_addr = _decode_x86_stub_target_ptr(
                    slice_blob,
                    stub_file_off,
                    stub_addr,
                    xor_key_hint=xor_key_hint,
                )
            else:
                ptr_addr = _decode_arm64_stub_target_ptr(
                    slice_blob,
                    stub_file_off,
                    stub_addr,
                    xor_key_hint=xor_key_hint,
                )
            if ptr_addr is None:
                continue

            name = ptr_to_name.get(ptr_addr)
            if name == "_mprotect":
                mprotect_stub = stub_addr
            elif name == "__dyld_get_image_vmaddr_slide":
                dyld_stub = stub_addr

            if mprotect_stub is not None and dyld_stub is not None:
                return mprotect_stub, dyld_stub

    if mprotect_stub is None:
        _vlog("dynamic: _mprotect stub not found; continuing without explicit mprotect hook")
    if dyld_stub is None:
        _vlog(
            "dynamic: __dyld_get_image_vmaddr_slide stub not found; "
            "continuing without explicit dyld hook"
        )
    return mprotect_stub, dyld_stub


def _run_dynamic_emulation(
    slice_blob: memoryview,
    arch: str,
    load_method: int,
    mprotect_stub: int | None,
    dyld_stub: int | None,
    timeout_ms: int,
    max_insn: int,
) -> tuple[bytes, int | None, int | None, str]:
    try:
        from unicorn import (
            Uc,
            UcError,
            UC_ARCH_ARM64,
            UC_ARCH_X86,
            UC_HOOK_CODE,
            UC_HOOK_MEM_UNMAPPED,
            UC_HOOK_MEM_WRITE,
            UC_MEM_WRITE,
            UC_MODE_64,
            UC_MODE_ARM,
        )
        from unicorn.arm64_const import (
            UC_ARM64_REG_PC,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X29,
            UC_ARM64_REG_X30,
        )
        from unicorn.x86_const import (
            UC_X86_REG_RAX,
            UC_X86_REG_RBP,
            UC_X86_REG_RDI,
            UC_X86_REG_RDX,
            UC_X86_REG_RIP,
            UC_X86_REG_RSI,
            UC_X86_REG_RSP,
        )
    except Exception as exc:
        raise DeobfuscationError(
            "dynamic mode requires Unicorn Python bindings (pip install unicorn)"
        ) from exc

    code_size = _align_up(max(len(slice_blob), PAGE_SIZE), PAGE_SIZE)
    if load_method < 0 or load_method >= code_size:
        raise DeobfuscationError(f"invalid load method address: 0x{load_method:x}")

    if arch == "x86_64":
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        stack_address = STACK_ADDRESS_X64
    elif arch == "arm64":
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        stack_address = STACK_ADDRESS_ARM64
    else:
        raise DeobfuscationError(f"dynamic mode unsupported arch: {arch}")

    uc.mem_map(CODE_ADDRESS, code_size)
    uc.mem_write(CODE_ADDRESS, bytes(slice_blob))
    uc.mem_map(stack_address, STACK_SIZE)

    stack_ptr = stack_address + (STACK_SIZE // 2)
    if arch == "x86_64":
        uc.reg_write(UC_X86_REG_RSP, stack_ptr)
        uc.reg_write(UC_X86_REG_RBP, stack_ptr)
    else:
        uc.reg_write(UC_ARM64_REG_SP, stack_ptr)
        uc.reg_write(UC_ARM64_REG_X29, stack_ptr)

    write_min: int | None = None
    write_max: int | None = None

    def hook_write(_uc, access, address, size, _value, _user_data):
        nonlocal write_min, write_max
        if access != UC_MEM_WRITE:
            return
        if CODE_ADDRESS <= address < CODE_ADDRESS + code_size:
            local_min = address - CODE_ADDRESS
            local_max = local_min + max(size, 1) - 1
            if write_min is None or local_min < write_min:
                write_min = local_min
            if write_max is None or local_max > write_max:
                write_max = local_max

    def _x64_force_return(retval: int) -> None:
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = int.from_bytes(uc.mem_read(rsp, 8), "little")
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RAX, retval)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)

    def _arm64_force_return(retval: int) -> None:
        lr = uc.reg_read(UC_ARM64_REG_X30)
        uc.reg_write(UC_ARM64_REG_X0, retval)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def hook_code(_uc, address, _size, _user_data):
        if mprotect_stub is not None and address == CODE_ADDRESS + mprotect_stub:
            if arch == "x86_64":
                _ = uc.reg_read(UC_X86_REG_RDI)
                _ = uc.reg_read(UC_X86_REG_RSI)
                _ = uc.reg_read(UC_X86_REG_RDX)
                _x64_force_return(0)
            else:
                _ = uc.reg_read(UC_ARM64_REG_X0)
                _ = uc.reg_read(UC_ARM64_REG_X1)
                _ = uc.reg_read(UC_ARM64_REG_X2)
                _arm64_force_return(0)
            return

        if dyld_stub is not None and address == CODE_ADDRESS + dyld_stub:
            if arch == "x86_64":
                _ = uc.reg_read(UC_X86_REG_RDI)
                _x64_force_return(1)
            else:
                _ = uc.reg_read(UC_ARM64_REG_X0)
                _arm64_force_return(1)

    def hook_unmapped(_uc, _type, _address, _size, _value, _user_data):
        return False

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_write, begin=CODE_ADDRESS, end=CODE_ADDRESS + code_size - 1)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

    timeout_us = max(timeout_ms, 0) * 1000
    insn_count = max(max_insn, 0)
    start = CODE_ADDRESS + load_method
    emu_status = "OK"
    try:
        uc.emu_start(start, CODE_ADDRESS + code_size, timeout=timeout_us, count=insn_count)
    except UcError as exc:
        # Some exceptions are expected after target code is dumped.
        emu_status = str(exc)

    dumped = bytes(uc.mem_read(CODE_ADDRESS, len(slice_blob)))
    return dumped, write_min, write_max, emu_status


def _ensure_unicorn_available() -> None:
    try:
        import unicorn  # noqa: F401
    except Exception as exc:
        raise DeobfuscationError(
            "dynamic mode requires Unicorn Python bindings (pip install unicorn)"
        ) from exc


def _patch_slice_dynamic(
    slice_blob: memoryview,
    slice_info: SliceInfo,
    timeout_ms: int,
    max_insn: int,
    xor_key_hint: int | None = None,
) -> DynamicSliceResult:
    header = _parse_macho_header_64(slice_blob)
    if _cpu_to_arch(header.cputype) != slice_info.arch:
        raise DeobfuscationError(
            f"slice CPU type mismatch in {slice_info.source} ({slice_info.arch})"
        )
    _vlog(
        f"{slice_info.source}: dynamic patch start arch={slice_info.arch} "
        f"slice_off=0x{slice_info.offset:x} slice_size=0x{slice_info.size:x} "
        f"timeout_ms={timeout_ms} max_insn={max_insn}"
    )

    meta = _parse_slice_meta(slice_blob, header)
    fixed_symbol_strings = _restore_symbol_strings(slice_blob, header, meta)
    fixed_section_names = _restore_section_names(slice_blob, meta)

    ptr_to_name = _parse_lazy_bind_symbol_map(slice_blob, meta)
    if not ptr_to_name:
        raise DeobfuscationError("failed to parse lazy bind information")
    mprotect_stub, dyld_stub = _locate_required_stubs(
        slice_blob,
        meta,
        ptr_to_name,
        slice_info.arch,
        xor_key_hint=xor_key_hint,
    )
    try:
        load_method = _locate_objc_load_method(
            slice_blob,
            header,
            meta,
            xor_key_hint=xor_key_hint,
        )
        _vlog(f"{slice_info.source}: dynamic entry from Objective-C load @ 0x{load_method:x}")
    except DeobfuscationError as exc:
        _vlog(f"{slice_info.source}: Objective-C load lookup failed: {exc}; trying __mod_init_func")
        load_method = _locate_mod_init_entry(
            slice_blob,
            header,
            meta,
            xor_key_hint=xor_key_hint,
        )
        _vlog(f"{slice_info.source}: dynamic entry from __mod_init_func @ 0x{load_method:x}")

    dumped, write_min, write_max, emu_status = _run_dynamic_emulation(
        slice_blob=slice_blob,
        arch=slice_info.arch,
        load_method=load_method,
        mprotect_stub=mprotect_stub,
        dyld_stub=dyld_stub,
        timeout_ms=timeout_ms,
        max_insn=max_insn,
    )
    slice_blob[:] = dumped

    return DynamicSliceResult(
        arch=slice_info.arch,
        source=slice_info.source,
        slice_offset=slice_info.offset,
        slice_size=slice_info.size,
        load_method=load_method,
        mprotect_stub=mprotect_stub,
        dyld_get_slide_stub=dyld_stub,
        fixed_symbol_strings=fixed_symbol_strings,
        fixed_section_names=fixed_section_names,
        write_min=write_min,
        write_max=write_max,
        emu_status=emu_status,
    )


def _iter_supported_slices(binary: memoryview) -> Iterable[SliceInfo]:
    if len(binary) < 8:
        raise DeobfuscationError("input is too small")

    magic_be = struct.unpack_from(">I", binary, 0)[0]

    if magic_be in (FAT_MAGIC, FAT_MAGIC_64) or magic_be in (FAT_CIGAM, FAT_CIGAM_64):
        is_64 = magic_be in (FAT_MAGIC_64, FAT_CIGAM_64)
        endian = ">" if magic_be in (FAT_MAGIC, FAT_MAGIC_64) else "<"

        nfat_arch = struct.unpack_from(f"{endian}I", binary, 4)[0]
        entry_size = 32 if is_64 else 20
        table_end = 8 + nfat_arch * entry_size
        if table_end > len(binary):
            raise DeobfuscationError("truncated fat header")

        for i in range(nfat_arch):
            off = 8 + i * entry_size
            if is_64:
                cputype, _cpusubtype, offset, size, _align, _reserved = struct.unpack_from(
                    f"{endian}iiQQII", binary, off
                )
            else:
                cputype, _cpusubtype, offset, size, _align = struct.unpack_from(
                    f"{endian}iiIII", binary, off
                )

            if offset < 0 or size <= 0:
                continue
            if offset + size > len(binary):
                continue

            arch = _cpu_to_arch(cputype)
            if arch is None:
                continue

            yield SliceInfo(
                arch=arch,
                cputype=cputype,
                offset=offset,
                size=size,
                source=f"fat[{i}]",
            )
        return

    header = _parse_macho_header_64(binary)
    arch = _cpu_to_arch(header.cputype)
    if arch is None:
        raise DeobfuscationError(
            f"unsupported thin Mach-O CPU type: 0x{header.cputype & 0xFFFFFFFF:08x}"
        )

    yield SliceInfo(
        arch=arch,
        cputype=header.cputype,
        offset=0,
        size=len(binary),
        source="thin",
    )


def _read_candidate_entries(
    slice_blob: memoryview,
    table_off: int,
    scan_end: int,
) -> tuple[int, list[int], int]:
    if table_off + 4 > len(slice_blob):
        raise DeobfuscationError("invalid table candidate offset")

    (obfuscated_count,) = struct.unpack_from("<I", slice_blob, table_off)
    if obfuscated_count == 0:
        raise DeobfuscationError("zero obfuscated count")

    entries: list[int] = []
    pos = table_off + 4
    dword_count = 0
    while pos + 4 <= scan_end and dword_count < MAX_TABLE_DWORDS:
        (value,) = struct.unpack_from("<I", slice_blob, pos)
        if value == 0:
            return obfuscated_count, entries, pos + 4
        entries.append(value)
        pos += 4
        dword_count += 1

    raise DeobfuscationError("unterminated candidate table")


def _resolve_chunk_start(
    raw_start: int,
    size: int,
    slice_info: SliceInfo,
    meta: ParsedSliceMeta,
    slice_len: int,
) -> int:
    # 1) Plain slice-local file offset.
    if raw_start >= 0 and raw_start + size <= slice_len:
        return raw_start

    # 2) Fat-global file offset that still points to this slice.
    local_start = raw_start - slice_info.offset
    if local_start >= 0 and local_start + size <= slice_info.size and local_start + size <= slice_len:
        return local_start

    # 3) VM address inside a file-backed segment: convert vmaddr -> fileoff.
    for seg in meta.segments:
        if seg.filesize <= 0:
            continue
        seg_vm_start = seg.vmaddr
        seg_vm_end = seg.vmaddr + seg.filesize
        if raw_start < seg_vm_start or raw_start + size > seg_vm_end:
            continue

        rel = raw_start - seg_vm_start
        file_start = seg.fileoff + rel
        if file_start >= 0 and file_start + size <= slice_len:
            return file_start

    raise DeobfuscationError(
        f"unable to map chunk offset 0x{raw_start:x} size=0x{size:x} to slice file range"
    )


def _decode_candidate_chunks(
    candidate: TableCandidate,
    table_start: int,
    slice_info: SliceInfo,
    meta: ParsedSliceMeta,
    slice_len: int,
) -> list[tuple[int, int]]:
    chunks: list[tuple[int, int]] = []
    for i in range(0, len(candidate.entries), 2):
        raw_start = candidate.entries[i] ^ candidate.xor_key
        size = candidate.entries[i + 1] ^ candidate.xor_key
        if size == 0:
            raise DeobfuscationError("obfuscation chunk has zero size")

        file_start = _resolve_chunk_start(
            raw_start=raw_start,
            size=size,
            slice_info=slice_info,
            meta=meta,
            slice_len=slice_len,
        )
        if file_start < table_start:
            raise DeobfuscationError("obfuscation chunk overlaps Mach-O headers/load commands")

        file_end = file_start + size
        # Table metadata itself should not be part of deobfuscation chunks.
        if not (file_end <= candidate.table_offset or file_start >= candidate.table_end):
            raise DeobfuscationError("obfuscation chunk overlaps metadata table")

        _vlog(
            f"{slice_info.source}: chunk[{i // 2}] raw=0x{raw_start:x} size=0x{size:x} "
            f"mapped_file=0x{file_start:x}"
        )
        chunks.append((file_start, size))
    return chunks


def _find_table_candidate(
    slice_blob: memoryview,
    table_start: int,
    slice_info: SliceInfo,
    meta: ParsedSliceMeta,
) -> tuple[TableCandidate, list[tuple[int, int]]]:
    if table_start + 4 > len(slice_blob):
        raise DeobfuscationError("invalid table start offset")

    scan_end = min(len(slice_blob), table_start + MAX_TABLE_SCAN)
    if scan_end - table_start < 8:
        raise DeobfuscationError("not enough room to scan obfuscation table")

    last_error: str | None = None
    seen_nonzero = False
    candidate_count = 0
    logged_rejects = 0
    for table_off in range(table_start, scan_end - 3, 4):
        (probe_value,) = struct.unpack_from("<I", slice_blob, table_off)
        if probe_value == 0:
            continue
        seen_nonzero = True
        candidate_count += 1
        try:
            obfuscated_count, entries_raw, table_end = _read_candidate_entries(
                slice_blob, table_off, scan_end
            )
            if len(entries_raw) < 2:
                continue
            if len(entries_raw) % 2 != 0:
                entries_raw = entries_raw[:-1]
            if len(entries_raw) < 2:
                continue

            pair_count = len(entries_raw) // 2
            if pair_count == 0:
                continue
            xor_key = (obfuscated_count ^ pair_count) & 0xFF
            candidate = TableCandidate(
                table_offset=table_off,
                table_end=table_end,
                obfuscated_count=obfuscated_count,
                xor_key=xor_key,
                entries=entries_raw,
            )
            chunks = _decode_candidate_chunks(
                candidate=candidate,
                table_start=table_start,
                slice_info=slice_info,
                meta=meta,
                slice_len=len(slice_blob),
            )
            _vlog(
                f"{slice_info.source}: selected table@0x{table_off:x} "
                f"table_end=0x{table_end:x} key=0x{xor_key:02x} pairs={pair_count} "
                f"scanned_candidates={candidate_count}"
            )
            return candidate, chunks
        except DeobfuscationError as exc:
            last_error = str(exc)
            if VERBOSE and logged_rejects < 12:
                _vlog(f"{slice_info.source}: reject table@0x{table_off:x}: {exc}")
                logged_rejects += 1
            continue

    if not seen_nonzero:
        raise DeobfuscationError("no obfuscation metadata table found")
    if last_error:
        raise DeobfuscationError(f"failed to locate valid obfuscation table: {last_error}")
    raise DeobfuscationError("failed to locate valid obfuscation table")


def _patch_slice(slice_blob: memoryview, slice_info: SliceInfo) -> SliceResult:
    header = _parse_macho_header_64(slice_blob)
    if _cpu_to_arch(header.cputype) != slice_info.arch:
        raise DeobfuscationError(
            f"slice CPU type mismatch in {slice_info.source} ({slice_info.arch})"
        )

    table_start = MACH_HEADER_64_SIZE + header.sizeofcmds
    if table_start >= len(slice_blob):
        raise DeobfuscationError("invalid sizeofcmds in Mach-O header")

    _vlog(
        f"{slice_info.source}: static patch start arch={slice_info.arch} "
        f"slice_off=0x{slice_info.offset:x} slice_size=0x{slice_info.size:x} "
        f"table_start=0x{table_start:x}"
    )

    meta_before = _parse_slice_meta(slice_blob, header)
    candidate, chunks = _find_table_candidate(
        slice_blob=slice_blob,
        table_start=table_start,
        slice_info=slice_info,
        meta=meta_before,
    )
    original_slice = bytes(slice_blob)
    patched = 0

    try:
        for file_start, size in chunks:
            end = file_start + size

            for idx in range(file_start, end):
                slice_blob[idx] ^= candidate.xor_key
            patched += size

        # Re-parse after patching to ensure we did not corrupt Mach-O headers.
        patched_header = _parse_macho_header_64(slice_blob)
        if (
            patched_header.cputype != header.cputype
            or patched_header.ncmds != header.ncmds
            or patched_header.sizeofcmds != header.sizeofcmds
        ):
            raise DeobfuscationError("post-patch Mach-O header mismatch")

        meta = _parse_slice_meta(slice_blob, patched_header)
        fixed_symbol_strings = _restore_symbol_strings(slice_blob, patched_header, meta)
        fixed_section_names = _restore_section_names(slice_blob, meta)
    except Exception as exc:
        # Never leave partially-corrupted output in memory.
        slice_blob[:] = original_slice
        if isinstance(exc, DeobfuscationError):
            raise
        raise DeobfuscationError(f"failed to patch slice {slice_info.source}: {exc}") from exc

    return SliceResult(
        arch=slice_info.arch,
        source=slice_info.source,
        slice_offset=slice_info.offset,
        slice_size=slice_info.size,
        xor_key=candidate.xor_key,
        pair_count=len(candidate.entries) // 2,
        patched_bytes=patched,
        table_offset=candidate.table_offset,
        fixed_symbol_strings=fixed_symbol_strings,
        fixed_section_names=fixed_section_names,
    )


def _format_result(result: SliceResult) -> str:
    return (
        f"[{result.source}] arch={result.arch} "
        f"slice_off=0x{result.slice_offset:x} key=0x{result.xor_key:02x} "
        f"chunks={result.pair_count} patched=0x{result.patched_bytes:x} "
        f"table_off=0x{result.table_offset:x} "
        f"symfix={result.fixed_symbol_strings} secfix={result.fixed_section_names}"
    )


def _format_dynamic_result(result: DynamicSliceResult) -> str:
    if result.write_min is None or result.write_max is None:
        write_info = "writes=none"
    else:
        write_info = f"writes=0x{result.write_min:x}-0x{result.write_max:x}"
    return (
        f"[{result.source}] arch={result.arch} mode=dynamic "
        f"slice_off=0x{result.slice_offset:x} entry=0x{result.load_method:x} "
        f"mprotect_stub={'none' if result.mprotect_stub is None else f'0x{result.mprotect_stub:x}'} "
        f"dyld_stub={'none' if result.dyld_get_slide_stub is None else f'0x{result.dyld_get_slide_stub:x}'} "
        f"symfix={result.fixed_symbol_strings} secfix={result.fixed_section_names} "
        f"{write_info} emu={result.emu_status}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="TNT deobfuscator for Mach-O x86_64/arm64 binaries (static/dynamic)"
    )
    parser.add_argument("-i", "--input", required=True, type=Path, help="input Mach-O binary")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output binary path (default: <input>.deobf)",
    )
    parser.add_argument(
        "--arch",
        choices=["all", "x86_64", "arm64"],
        default="all",
        help="target arch filter (for fat binaries)",
    )
    parser.add_argument(
        "--mode",
        choices=["static", "dynamic"],
        default="static",
        help="processing mode: static XOR recovery or dynamic Unicorn emulation",
    )
    parser.add_argument(
        "--emu-timeout-ms",
        type=int,
        default=None,
        help=(
            "dynamic mode emulation timeout in milliseconds "
            f"(default: {DEFAULT_DYNAMIC_TIMEOUT_MS}; 0 = unlimited)"
        ),
    )
    parser.add_argument(
        "--emu-max-insn",
        type=int,
        default=None,
        help=(
            "dynamic mode instruction count limit "
            f"(default: {DEFAULT_DYNAMIC_MAX_INSN}; 0 = unlimited)"
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="enable verbose diagnostic logs (stderr)",
    )

    args = parser.parse_args(argv)
    global VERBOSE
    VERBOSE = bool(args.verbose)

    in_path: Path = args.input
    out_path: Path = args.output if args.output else Path(f"{in_path}.deobf")

    dynamic_timeout_ms = (
        args.emu_timeout_ms
        if args.emu_timeout_ms is not None
        else DEFAULT_DYNAMIC_TIMEOUT_MS
    )
    dynamic_max_insn = (
        args.emu_max_insn
        if args.emu_max_insn is not None
        else DEFAULT_DYNAMIC_MAX_INSN
    )

    _vlog(
        f"input={in_path} output={out_path} mode={args.mode} arch={args.arch} "
        f"timeout_ms={dynamic_timeout_ms} max_insn={dynamic_max_insn}"
    )
    if args.mode == "dynamic" and dynamic_timeout_ms == 0 and dynamic_max_insn == 0:
        print(
            "[WARN] dynamic mode is configured as unlimited "
            "(--emu-timeout-ms=0 and --emu-max-insn=0); this may run indefinitely.",
            file=sys.stderr,
        )

    try:
        raw = bytearray(in_path.read_bytes())
    except OSError as exc:
        print(f"[ERROR] failed to read input: {exc}", file=sys.stderr)
        return 1

    try:
        all_slices = list(_iter_supported_slices(memoryview(raw)))
        if not all_slices:
            raise DeobfuscationError("no supported x86_64/arm64 slices found")

        if args.arch == "all":
            target_slices = all_slices
        else:
            target_slices = [s for s in all_slices if s.arch == args.arch]

        if not target_slices:
            raise DeobfuscationError(f"no slice matched --arch={args.arch}")
        _vlog(
            "target slices: "
            + ", ".join(
                f"{s.source}:{s.arch}@0x{s.offset:x}+0x{s.size:x}" for s in target_slices
            )
        )

        if args.mode == "static":
            static_results: list[SliceResult] = []
            static_failures: list[str] = []
            for slice_info in target_slices:
                view = memoryview(raw)[slice_info.offset : slice_info.offset + slice_info.size]
                try:
                    static_results.append(_patch_slice(view, slice_info))
                except DeobfuscationError as exc:
                    # In multi-arch mode, allow one slice to fail without corrupting output.
                    if args.arch == "all" and len(target_slices) > 1:
                        static_failures.append(f"[{slice_info.source}] {exc}")
                        continue
                    raise
            for failure in static_failures:
                print(f"[WARN] static mode skipped slice: {failure}", file=sys.stderr)
            if not static_results:
                if static_failures:
                    joined = "; ".join(static_failures)
                    raise DeobfuscationError(f"no slice was patched successfully: {joined}")
                raise DeobfuscationError("no slice was patched successfully")
            dynamic_results: list[DynamicSliceResult] = []
        else:
            _ensure_unicorn_available()
            dynamic_results = []
            dynamic_failures: list[str] = []
            for slice_info in target_slices:
                view = memoryview(raw)[slice_info.offset : slice_info.offset + slice_info.size]
                original_slice = bytes(view)
                try:
                    # Prime dynamic mode with static metadata-based deobfuscation when available.
                    # This helps resolve stub patterns/symbol info in binaries where these bytes
                    # are still obfuscated before emulation.
                    prime_key: int | None = None
                    try:
                        prime_result = _patch_slice(view, slice_info)
                        prime_key = prime_result.xor_key
                        _vlog(
                            f"{slice_info.source}: dynamic prime succeeded "
                            f"key=0x{prime_result.xor_key:02x} patched=0x{prime_result.patched_bytes:x}"
                        )
                    except DeobfuscationError as exc:
                        _vlog(f"{slice_info.source}: dynamic prime skipped: {exc}")

                    dynamic_results.append(
                        _patch_slice_dynamic(
                            view,
                            slice_info,
                            timeout_ms=dynamic_timeout_ms,
                            max_insn=dynamic_max_insn,
                            xor_key_hint=prime_key,
                        )
                    )
                except DeobfuscationError as exc:
                    # Restore untouched bytes when skipping a failed slice in multi-arch mode.
                    view[:] = original_slice
                    if args.arch == "all" and len(target_slices) > 1:
                        dynamic_failures.append(f"[{slice_info.source}] {exc}")
                        continue
                    raise
            for failure in dynamic_failures:
                print(f"[WARN] dynamic mode skipped slice: {failure}", file=sys.stderr)
            if not dynamic_results:
                if dynamic_failures:
                    joined = "; ".join(dynamic_failures)
                    raise DeobfuscationError(f"no slice was dynamically patched successfully: {joined}")
                raise DeobfuscationError("no slice was dynamically patched successfully")
            static_results = []

    except DeobfuscationError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    try:
        out_path.write_bytes(raw)
    except OSError as exc:
        print(f"[ERROR] failed to write output: {exc}", file=sys.stderr)
        return 1

    if args.mode == "static":
        for result in static_results:
            print(_format_result(result))
    else:
        for result in dynamic_results:
            print(_format_dynamic_result(result))
    print(f"[OK] wrote deobfuscated file: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

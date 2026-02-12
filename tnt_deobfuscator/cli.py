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
import time
from pathlib import Path
from typing import Iterable

from tnt_deobfuscator.installer import install_ida_plugin, uninstall_ida_plugin


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
STACK_ADDRESS_ARM64_THREAD = 0x68000000
STACK_SIZE = 10 * 1024 * 1024
HEAP_ADDRESS = 0x50000000
HEAP_SIZE = 32 * 1024 * 1024
THREAD_TRAMPOLINE_ADDRESS = HEAP_ADDRESS + HEAP_SIZE + PAGE_SIZE

DEFAULT_DYNAMIC_TIMEOUT_MS = 30000
DEFAULT_DYNAMIC_MAX_INSN = 2000000

VERBOSE = False
REPROCESS_NAME_HINTS = (".deobf", ".strfix", ".analysis", ".runnable")


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
    static_strings_found: int
    static_strings_applied: int
    static_key_patches: int


@dataclasses.dataclass(frozen=True)
class DynamicSliceResult:
    arch: str
    source: str
    slice_offset: int
    slice_size: int
    load_method: int
    mprotect_stub: int | None
    mprotect_stub_symbol: str | None
    dyld_get_slide_stub: int | None
    dyld_get_slide_stub_symbol: str | None
    fixed_symbol_strings: int
    fixed_section_names: int
    write_min: int | None
    write_max: int | None
    emu_status: str
    runtime_string_layer: str
    runtime_strings_found: int
    runtime_strings_applied: int
    runtime_key_patches: int


@dataclasses.dataclass(frozen=True)
class RuntimeStringCandidate:
    file_offset: int
    end_offset: int
    key: int
    decoded: str
    imm_patch_offset: int | None


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


def _parse_indirect_lazy_symbol_map(
    slice_blob: memoryview,
    header: MachOHeader64,
    meta: ParsedSliceMeta,
) -> dict[int, str]:
    if (
        meta.symoff is None
        or meta.stroff is None
        or meta.indirectsymoff is None
        or meta.nsyms <= 0
        or meta.nindirectsyms <= 0
        or meta.strsize <= 0
        or not meta.lazy_symbol_sections
    ):
        return {}

    symtab_end = meta.symoff + meta.nsyms * MACH_NLIST_64_SIZE
    strtab_end = meta.stroff + meta.strsize
    indirect_end = meta.indirectsymoff + meta.nindirectsyms * 4
    if symtab_end > len(slice_blob) or strtab_end > len(slice_blob) or indirect_end > len(slice_blob):
        return {}

    endian = header.endian
    addr_map: dict[int, str] = {}
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

            nlist_off = meta.symoff + symbol_index * MACH_NLIST_64_SIZE
            (strx,) = struct.unpack_from(f"{endian}I", slice_blob, nlist_off)
            if strx >= meta.strsize:
                continue
            name_off = meta.stroff + strx
            try:
                symbol_name, _ = _read_c_string(slice_blob, name_off, strtab_end)
            except DeobfuscationError:
                continue
            if not symbol_name:
                continue

            ptr_addr = section.addr + i * POINTER_SIZE_64
            addr_map[ptr_addr] = symbol_name
    return addr_map


def _parse_lazy_bind_symbol_map(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
    header: MachOHeader64 | None = None,
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

    if header is not None:
        for ptr_addr, symbol_name in _parse_indirect_lazy_symbol_map(
            slice_blob,
            header,
            meta,
        ).items():
            prev = addr_map.get(ptr_addr)
            if prev is None:
                addr_map[ptr_addr] = symbol_name
                continue
            prev_printable = sum(1 for ch in prev if 32 <= ord(ch) <= 126)
            new_printable = sum(1 for ch in symbol_name if 32 <= ord(ch) <= 126)
            prev_score = (8 if prev.startswith("_") else 0) + prev_printable - (10 if "�" in prev else 0)
            new_score = (
                (8 if symbol_name.startswith("_") else 0)
                + new_printable
                - (10 if "�" in symbol_name else 0)
            )
            if new_score > prev_score:
                addr_map[ptr_addr] = symbol_name
    return addr_map


def _canonical_import_symbol_name(name: str) -> str:
    symbol = (name or "").strip()
    if not symbol:
        return symbol
    for sep in ("$", "@"):
        pos = symbol.find(sep)
        if pos > 0:
            symbol = symbol[:pos]
    return symbol


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
        ptr_to_name = _parse_lazy_bind_symbol_map(slice_blob, meta, header=header)
    except DeobfuscationError as exc:
        print(f"[WARN] symbol restore skipped: {exc}", file=sys.stderr)
        return 0
    if not ptr_to_name:
        return 0

    fixed = 0
    written_offsets: set[int] = set()
    name_to_string_off: dict[str, int] = {}
    endian = header.endian
    str_alloc_cursor = meta.stroff

    def _alloc_string_slot(new_bytes: bytes) -> int | None:
        nonlocal str_alloc_cursor
        needed = len(new_bytes) + 1
        scan = max(str_alloc_cursor, meta.stroff + 1)
        end_limit = strtab_end - needed
        while scan <= end_limit:
            if slice_blob[scan] != 0:
                scan += 1
                continue
            run_end = scan
            while run_end < strtab_end and slice_blob[run_end] == 0 and (run_end - scan) < needed:
                run_end += 1
            if run_end - scan >= needed:
                str_alloc_cursor = run_end
                return scan
            scan = max(run_end + 1, scan + 1)
        return None

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

            reused_off = name_to_string_off.get(name)
            if reused_off is not None:
                new_strx = reused_off - meta.stroff
                struct.pack_into(f"{endian}I", slice_blob, nlist_off, new_strx)
                fixed += 1
                continue

            cur_end = string_off
            while cur_end < strtab_end and slice_blob[cur_end] != 0:
                cur_end += 1
            if cur_end >= strtab_end:
                continue

            old_len = cur_end - string_off
            new_bytes = name.encode("utf-8", "replace")
            # Keep replacement safe: don't overwrite neighboring strings.
            if len(new_bytes) <= old_len:
                slice_blob[string_off : string_off + len(new_bytes)] = new_bytes
                for p in range(string_off + len(new_bytes), cur_end):
                    slice_blob[p] = 0
                fixed += 1
                written_offsets.add(string_off)
                name_to_string_off[name] = string_off
                continue

            alloc_off = _alloc_string_slot(new_bytes)
            if alloc_off is None:
                continue
            slice_blob[alloc_off : alloc_off + len(new_bytes)] = new_bytes
            slice_blob[alloc_off + len(new_bytes)] = 0
            new_strx = alloc_off - meta.stroff
            struct.pack_into(f"{endian}I", slice_blob, nlist_off, new_strx)
            fixed += 1
            written_offsets.add(alloc_off)
            name_to_string_off[name] = alloc_off

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
    METHOD_LIST_FLAG_SMALL = 0x80000000

    def xor_u64(value: int) -> int:
        if xor_key_hint is None:
            return value
        mask = int.from_bytes(bytes([xor_key_hint]) * 8, "little")
        return value ^ mask

    def select_mapped_ptr(raw_value: int) -> int:
        if raw_value == 0:
            return 0
        candidates = [raw_value]
        if xor_key_hint is not None:
            candidates.append(xor_u64(raw_value))
        for cand in candidates:
            if _va_to_file_offset(meta, cand) is not None:
                return cand
        raise DeobfuscationError("pointer outside mapped range")

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
    class_info_ptr = select_mapped_ptr(class_info_ptr_raw)
    if class_info_ptr == 0:
        raise DeobfuscationError("Objective-C class info pointer is null")

    info_file_off = _va_to_file_offset(meta, class_info_ptr)
    if info_file_off is None:
        raise DeobfuscationError("invalid Objective-C class info pointer")

    # struct __objc2_class_ro: base_meths pointer at +0x20.
    # On modern arm64 binaries this often points into __TEXT,__objc_methlist.
    base_meths_ptr_raw = _read_u64(slice_blob, info_file_off + 0x20, header.endian)
    base_meths_ptr = select_mapped_ptr(base_meths_ptr_raw)
    if base_meths_ptr == 0:
        raise DeobfuscationError("Objective-C base methods pointer is null")
    meths_file_off = _va_to_file_offset(meta, base_meths_ptr)
    if meths_file_off is None:
        raise DeobfuscationError("Objective-C methods pointer is outside mapped segments")

    # struct method_list_t { uint32 entsizeAndFlags; uint32 count; }
    entsize_and_flags = _read_u32(slice_blob, meths_file_off, header.endian)
    meth_count = _read_u32(slice_blob, meths_file_off + 4, header.endian)
    if meth_count < 1:
        raise DeobfuscationError("Objective-C methods list is empty")
    entry_size = entsize_and_flags & 0x00FFFFFF
    is_small_method_list = (entsize_and_flags & METHOD_LIST_FLAG_SMALL) != 0
    if entry_size <= 0:
        entry_size = 12 if is_small_method_list else 24

    def read_method_name(name_ptr: int, small_list: bool) -> str | None:
        candidates = [name_ptr]
        if small_list:
            # small/relative method lists typically store selector refs
            # (pointer to C-string pointer) rather than C-string pointers directly.
            name_file_off = _va_to_file_offset(meta, name_ptr)
            if name_file_off is not None and name_file_off + 8 <= len(slice_blob):
                sel_name_ptr = _read_u64(slice_blob, name_file_off, header.endian)
                if sel_name_ptr != 0:
                    candidates.append(sel_name_ptr)
        for candidate in candidates:
            file_off = _va_to_file_offset(meta, candidate)
            if file_off is None:
                continue
            parsed = _read_nul_terminated(slice_blob, file_off, max_len=128)
            if parsed is None:
                continue
            data, _ = parsed
            try:
                name = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if name:
                return name
        return None

    chosen_imp: int | None = None
    for i in range(meth_count):
        method_off = meths_file_off + 8 + (i * entry_size)
        if method_off < 0 or method_off >= len(slice_blob):
            break

        if is_small_method_list:
            if method_off + 12 > len(slice_blob):
                break
            name_rel = struct.unpack_from(f"{header.endian}i", slice_blob, method_off)[0]
            imp_rel = struct.unpack_from(f"{header.endian}i", slice_blob, method_off + 8)[0]
            name_ptr = (method_off + name_rel) & 0xFFFFFFFFFFFFFFFF
            imp_ptr = (method_off + 8 + imp_rel) & 0xFFFFFFFFFFFFFFFF
        else:
            if method_off + 24 > len(slice_blob):
                break
            name_ptr_raw = _read_u64(slice_blob, method_off, header.endian)
            try:
                name_ptr = select_mapped_ptr(name_ptr_raw)
            except DeobfuscationError:
                name_ptr = name_ptr_raw
            imp_ptr = _read_u64(slice_blob, method_off + 16, header.endian)

        try:
            imp_addr = select_exec_addr(imp_ptr)
        except DeobfuscationError:
            continue

        if chosen_imp is None:
            chosen_imp = imp_addr

        method_name = read_method_name(name_ptr, is_small_method_list)
        if method_name == "load":
            return imp_addr

    if chosen_imp is not None:
        return chosen_imp
    raise DeobfuscationError("no executable Objective-C method implementation found")


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

    def decode_adrp_ldr_br(insn_1: int, insn_2: int, insn_3: int) -> int | None:
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

    def decode_ldr_literal_br(_insn_1: int, insn_2: int, insn_3: int) -> int | None:
        # Common modern stub shape:
        #   NOP/BTI
        #   LDR Xt, #imm19
        #   BR  Xt
        if (insn_3 & 0xFFFFFC1F) != 0xD61F0000:
            return None
        reg_br = (insn_3 >> 5) & 0x1F

        # LDR (literal), 64-bit register variant.
        if (insn_2 & 0xFF000000) != 0x58000000:
            return None
        reg_t = insn_2 & 0x1F
        if reg_t != reg_br:
            return None

        imm_19 = (insn_2 >> 5) & 0x7FFFF
        disp = _sign_extend(imm_19, 19) << 2
        literal_insn_addr = stub_addr + 4
        return (literal_insn_addr + disp) & 0xFFFFFFFFFFFFFFFF

    result = decode_adrp_ldr_br(*words)
    if result is None:
        result = decode_ldr_literal_br(*words)
    if result is not None:
        return result
    if xor_key_hint is None:
        return None

    key_mask = int.from_bytes(bytes([xor_key_hint]) * 4, "little")
    deobf_words = tuple(w ^ key_mask for w in words)
    result = decode_adrp_ldr_br(*deobf_words)
    if result is not None:
        return result
    return decode_ldr_literal_br(*deobf_words)


def _locate_required_stubs(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
    ptr_to_name: dict[int, str],
    arch: str,
    xor_key_hint: int | None = None,
) -> tuple[int | None, int | None, dict[int, str], dict[int, str]]:
    if not meta.stubs_sections:
        raise DeobfuscationError("missing __stubs section for dynamic mode")

    protect_candidates: dict[str, int] = {}
    mprotect_stub: int | None = None
    dyld_stub: int | None = None
    stub_name_by_addr: dict[int, str] = {}
    ptr_name_by_addr: dict[int, str] = {}

    for stubs in meta.stubs_sections:
        stub_size = stubs.reserved2
        if stub_size <= 0:
            if arch == "x86_64":
                stub_size = 6
            elif arch == "arm64":
                stub_size = 12
            else:
                raise DeobfuscationError(f"dynamic mode unsupported arch: {arch}")
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
            elif arch == "arm64":
                ptr_addr = _decode_arm64_stub_target_ptr(
                    slice_blob,
                    stub_file_off,
                    stub_addr,
                    xor_key_hint=xor_key_hint,
                )
            else:
                raise DeobfuscationError(f"dynamic mode unsupported arch: {arch}")
            if ptr_addr is None:
                continue

            raw_name = ptr_to_name.get(ptr_addr)
            name = _canonical_import_symbol_name(raw_name) if raw_name else None
            if name:
                stub_name_by_addr.setdefault(stub_addr, name)
                ptr_name_by_addr.setdefault(ptr_addr, name)
            if name in {"_mprotect", "_vm_protect"}:
                protect_candidates.setdefault(name, stub_addr)
                if mprotect_stub is None:
                    mprotect_stub = stub_addr
            elif name == "__dyld_get_image_vmaddr_slide":
                dyld_stub = stub_addr

    if arch == "x86_64":
        protect_prefer = ("_mprotect", "_vm_protect")
    elif arch == "arm64":
        protect_prefer = ("_vm_protect", "_mprotect")
    else:
        protect_prefer = ("_mprotect", "_vm_protect")
    for symbol_name in protect_prefer:
        if symbol_name in protect_candidates:
            mprotect_stub = protect_candidates[symbol_name]
            break

    if mprotect_stub is None:
        _vlog(
            "dynamic: protection stub not found "
            "(_vm_protect/_mprotect); continuing without explicit mprotect hook"
        )
    else:
        if VERBOSE and len(protect_candidates) > 1:
            all_candidates = ", ".join(
                f"{name}@0x{off:x}" for name, off in sorted(protect_candidates.items())
            )
            _vlog(f"dynamic: protection stub candidates {{{all_candidates}}}")
        selected = stub_name_by_addr.get(mprotect_stub, "unknown")
        _vlog(f"dynamic: protection stub selected {selected} @ 0x{mprotect_stub:x}")
    if dyld_stub is None:
        _vlog(
            "dynamic: __dyld_get_image_vmaddr_slide stub not found; "
            "continuing without explicit dyld hook"
        )
    else:
        selected = stub_name_by_addr.get(dyld_stub, "unknown")
        _vlog(f"dynamic: dyld slide stub selected {selected} @ 0x{dyld_stub:x}")
    return mprotect_stub, dyld_stub, stub_name_by_addr, ptr_name_by_addr


def _va_to_file_offset(meta: ParsedSliceMeta, va: int) -> int | None:
    for seg in meta.segments:
        if seg.filesize <= 0:
            continue
        seg_start = seg.vmaddr
        seg_end = seg.vmaddr + seg.filesize
        if seg_start <= va < seg_end:
            return seg.fileoff + (va - seg_start)
    return None


def _collect_exec_overlay_ranges(meta: ParsedSliceMeta, slice_len: int) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for section in meta.sections:
        if section.size <= 0:
            continue
        start = section.offset
        end = section.offset + section.size
        if start < 0 or end > slice_len or start >= end:
            continue
        if not (section.seg_maxprot & VM_PROT_EXECUTE):
            continue
        sect_type = section.flags & SECTION_TYPE
        if sect_type == S_CSTRING_LITERALS:
            continue
        if _section_has_instructions(section) or sect_type == S_SYMBOL_STUBS:
            ranges.append((start, end))

    if not ranges:
        for seg in meta.segments:
            if seg.filesize <= 0:
                continue
            start = seg.fileoff
            end = seg.fileoff + seg.filesize
            if start < 0 or end > slice_len or start >= end:
                continue
            if seg.maxprot & VM_PROT_EXECUTE:
                ranges.append((start, end))

    if not ranges:
        return []
    ranges.sort()
    merged: list[list[int]] = [[ranges[0][0], ranges[0][1]]]
    for start, end in ranges[1:]:
        last = merged[-1]
        if start <= last[1]:
            if end > last[1]:
                last[1] = end
            continue
        merged.append([start, end])
    return [(item[0], item[1]) for item in merged]


def _overlay_dump_ranges(
    slice_blob: memoryview,
    dumped: bytes,
    ranges: list[tuple[int, int]],
) -> int:
    changed = 0
    for start, end in ranges:
        if start < 0 or end > len(slice_blob) or start >= end:
            continue
        if bytes(slice_blob[start:end]) != dumped[start:end]:
            slice_blob[start:end] = dumped[start:end]
            changed += end - start
    return changed


def _read_nul_terminated(
    slice_blob: memoryview,
    start: int,
    max_len: int = 512,
) -> tuple[bytes, int] | None:
    if start < 0 or start >= len(slice_blob):
        return None
    pos = start
    end = min(len(slice_blob), start + max_len)
    while pos < end and slice_blob[pos] != 0:
        pos += 1
    if pos == start or pos >= end:
        return None
    return bytes(slice_blob[start:pos]), pos


def _looks_decoded_text(data: bytes) -> bool:
    if not data:
        return False

    printable = 0
    alpha = 0
    for b in data:
        if 32 <= b <= 126:
            printable += 1
            if (65 <= b <= 90) or (97 <= b <= 122):
                alpha += 1

    printable_ratio = printable / len(data)
    if printable_ratio < 0.9:
        return False
    if alpha < 4:
        return False
    return True


def _extract_runtime_string_candidates_x86(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
) -> list[RuntimeStringCandidate]:
    candidates: dict[int, RuntimeStringCandidate] = {}

    for section in meta.sections:
        if section.size <= 0:
            continue
        if section.offset < 0 or section.offset + section.size > len(slice_blob):
            continue
        if not (section.seg_maxprot & VM_PROT_EXECUTE):
            continue

        sec_start = section.offset
        sec_end = section.offset + section.size
        # Pattern:
        #   48 8D 0D xx xx xx xx    lea rcx, [rip+disp32]
        #   0F BE|B6 04 01          movsx/movzx eax, byte ptr [rcx+rax]
        #   83 F0 kk                xor eax, imm8
        #   ... 88 04 11            mov byte ptr [rcx+rdx], al
        for off in range(sec_start + 7, sec_end - 32):
            if slice_blob[off] != 0x0F:
                continue
            if slice_blob[off + 1] not in (0xBE, 0xB6):
                continue
            if bytes(slice_blob[off + 2 : off + 6]) != b"\x04\x01\x83\xf0":
                continue

            key = slice_blob[off + 6]
            if key == 0:
                continue

            # Keep confidence high: require the store pattern shortly after.
            window = bytes(slice_blob[off + 7 : off + 28])
            if b"\x88\x04\x11" not in window:
                continue

            lea_off = off - 7
            if bytes(slice_blob[lea_off : lea_off + 3]) != b"\x48\x8D\x0D":
                continue

            disp = struct.unpack_from("<i", slice_blob, lea_off + 3)[0]
            lea_va = section.addr + (lea_off - section.offset)
            target_va = lea_va + 7 + disp
            target_off = _va_to_file_offset(meta, target_va)
            if target_off is None:
                continue

            read = _read_nul_terminated(slice_blob, target_off)
            if read is None:
                continue
            raw, end_off = read
            if len(raw) < 6:
                continue

            decoded_bytes = bytes(b ^ key for b in raw)
            if not _looks_decoded_text(decoded_bytes):
                continue

            decoded = decoded_bytes.decode("ascii", "replace")
            prev = candidates.get(target_off)
            if prev is None:
                candidates[target_off] = RuntimeStringCandidate(
                    file_offset=target_off,
                    end_offset=end_off,
                    key=key,
                    decoded=decoded,
                    imm_patch_offset=off + 6,
                )

    return sorted(candidates.values(), key=lambda item: item.file_offset)


def _arm64_decode_adr_like_target(insn: int, pc: int) -> tuple[int, int] | None:
    op = insn & 0x9F000000
    if op not in {0x10000000, 0x90000000}:
        return None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = _sign_extend((immhi << 2) | immlo, 21)
    if op == 0x90000000:
        target = (pc & ~0xFFF) + (imm << 12)
    else:
        target = pc + imm
    return rd, target & 0xFFFFFFFFFFFFFFFF


def _arm64_decode_add_imm_x(insn: int) -> tuple[int, int, int] | None:
    if ((insn >> 31) & 1) != 1:
        return None
    if ((insn >> 30) & 1) != 0:  # add/sub immediate: op bit
        return None
    if ((insn >> 29) & 1) != 0:  # set-flags bit
        return None
    if (insn & 0x1F000000) != 0x11000000:
        return None
    rd = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm12 = (insn >> 10) & 0xFFF
    shift = (insn >> 22) & 0x1
    imm = imm12 << (12 if shift else 0)
    return rd, rn, imm


def _arm64_decode_add_reg_x(insn: int) -> tuple[int, int, int] | None:
    # ADD Xd, Xn, Xm, LSL #0
    if (insn & 0xFFE0FC00) != 0x8B000000:
        return None
    rd = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    rm = (insn >> 16) & 0x1F
    return rd, rn, rm


def _arm64_decode_ldrsb_w(insn: int) -> tuple[int, int] | None:
    # LDRSB Wt, [Xn, #imm]
    if (insn & 0xFFC00000) != 0x39C00000:
        return None
    imm12 = (insn >> 10) & 0xFFF
    if imm12 != 0:
        return None
    rt = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    return rt, rn


def _arm64_decode_mov_imm_w(insn: int) -> tuple[int, int] | None:
    # MOVN/MOVZ aliases.
    opcode = insn & 0x7F800000
    if opcode not in {0x12800000, 0x52800000}:
        return None
    rd = insn & 0x1F
    imm16 = (insn >> 5) & 0xFFFF
    hw = (insn >> 21) & 0x3
    shift = hw * 16
    if shift > 16:
        return None
    if opcode == 0x12800000:  # MOVN
        value = (~(imm16 << shift)) & 0xFFFFFFFF
    else:  # MOVZ
        value = (imm16 << shift) & 0xFFFFFFFF
    return rd, value


def _arm64_decode_eor_w(insn: int) -> tuple[int, int, int] | None:
    # EOR Wd, Wn, Wm, LSL #0
    if (insn & 0xFFE0FC00) != 0x4A000000:
        return None
    rd = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    rm = (insn >> 16) & 0x1F
    return rd, rn, rm


def _section_has_instructions(section: SectionInfo) -> bool:
    attrs = section.flags & SECTION_ATTRIBUTES
    if attrs & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS):
        return True
    return section.sectname == "__text"


def _arm64_file_off_is_executable(meta: ParsedSliceMeta, file_off: int) -> bool:
    for section in meta.sections:
        if section.size <= 0:
            continue
        start = section.offset
        end = section.offset + section.size
        if start <= file_off < end:
            if (section.flags & SECTION_TYPE) == S_CSTRING_LITERALS:
                return False
            return _section_has_instructions(section)
    for seg in meta.segments:
        if seg.filesize <= 0:
            continue
        start = seg.fileoff
        end = seg.fileoff + seg.filesize
        if start <= file_off < end:
            return bool(seg.maxprot & VM_PROT_EXECUTE)
    return False


def _arm64_infer_blob_base_va(
    slice_blob: memoryview,
    section_start: int,
    ldr_off: int,
    base_reg: int,
) -> int | None:
    cursor = ldr_off - 8
    search_start = max(section_start, ldr_off - 0x50)
    pending_add = 0
    while cursor >= search_start:
        insn = struct.unpack_from("<I", slice_blob, cursor)[0]
        add_imm = _arm64_decode_add_imm_x(insn)
        if add_imm is not None:
            rd, rn, imm = add_imm
            if rd == base_reg and rn == base_reg:
                pending_add += imm
                cursor -= 4
                continue
        adr_like = _arm64_decode_adr_like_target(insn, cursor)
        if adr_like is not None:
            rd, target = adr_like
            if rd == base_reg:
                return (target + pending_add) & 0xFFFFFFFFFFFFFFFF
        cursor -= 4
    return None


def _arm64_decode_blob_until_nul(
    slice_blob: memoryview,
    start: int,
    key: int,
    max_len: int = 256,
) -> tuple[bytes, int] | None:
    if start < 0 or start >= len(slice_blob):
        return None
    end = start
    limit = min(len(slice_blob), start + max_len)
    while end < limit and slice_blob[end] != 0:
        end += 1
    if end == start or end >= limit:
        return None
    raw = bytes(slice_blob[start:end])
    if len(raw) < 6:
        return None
    decoded = bytes((b ^ key) & 0xFF for b in raw)
    if not _looks_decoded_text(decoded):
        return None
    return decoded, end


def _extract_runtime_string_candidates_arm64(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
) -> list[RuntimeStringCandidate]:
    candidates: dict[int, RuntimeStringCandidate] = {}
    for section in meta.sections:
        if section.size <= 0:
            continue
        if section.offset < 0 or section.offset + section.size > len(slice_blob):
            continue
        if not _section_has_instructions(section):
            continue

        sec_start = section.offset
        sec_end = section.offset + section.size
        for off in range(sec_start + 4, sec_end - 8, 4):
            ldr_info = _arm64_decode_ldrsb_w(struct.unpack_from("<I", slice_blob, off)[0])
            if ldr_info is None:
                continue
            rt, _rn = ldr_info

            mov_off = off + 4
            mov_info = _arm64_decode_mov_imm_w(struct.unpack_from("<I", slice_blob, mov_off)[0])
            if mov_info is None:
                continue
            key_reg, mov_val = mov_info
            key = mov_val & 0xFF
            if key == 0:
                continue

            eor_info = _arm64_decode_eor_w(struct.unpack_from("<I", slice_blob, off + 8)[0])
            if eor_info is None:
                continue
            rd, rn, rm = eor_info
            if rd != rt or rn != rt or rm != key_reg:
                continue

            add_reg_info = _arm64_decode_add_reg_x(struct.unpack_from("<I", slice_blob, off - 4)[0])
            if add_reg_info is None:
                continue
            add_rd, add_rn, add_rm = add_reg_info
            if add_rd != rt or add_rm != rt:
                continue

            base_va = _arm64_infer_blob_base_va(
                slice_blob=slice_blob,
                section_start=sec_start,
                ldr_off=off,
                base_reg=add_rn,
            )
            if base_va is None:
                continue

            blob_off = _va_to_file_offset(meta, base_va)
            if blob_off is None:
                continue
            if _arm64_file_off_is_executable(meta, blob_off):
                continue

            decoded_info = _arm64_decode_blob_until_nul(slice_blob, blob_off, key)
            if decoded_info is None:
                continue
            decoded_bytes, end_off = decoded_info
            decoded = decoded_bytes.decode("ascii", "replace")

            prev = candidates.get(blob_off)
            if prev is None or (end_off - blob_off) > (prev.end_offset - prev.file_offset):
                candidates[blob_off] = RuntimeStringCandidate(
                    file_offset=blob_off,
                    end_offset=end_off,
                    key=key,
                    decoded=decoded,
                    imm_patch_offset=mov_off,
                )

    return sorted(candidates.values(), key=lambda item: item.file_offset)


def _extract_runtime_string_candidates(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
    arch: str,
) -> list[RuntimeStringCandidate]:
    if arch == "x86_64":
        return _extract_runtime_string_candidates_x86(slice_blob, meta)
    if arch == "arm64":
        return _extract_runtime_string_candidates_arm64(slice_blob, meta)
    return []


def _apply_runtime_string_candidates(
    slice_blob: memoryview,
    candidates: list[RuntimeStringCandidate],
) -> int:
    applied = 0
    for item in candidates:
        if item.file_offset < 0 or item.end_offset > len(slice_blob) or item.end_offset <= item.file_offset:
            continue
        raw = bytes(slice_blob[item.file_offset : item.end_offset])
        if not raw:
            continue

        if item.key == 0:
            decoded = item.decoded.encode("ascii", "replace")
            if len(decoded) != len(raw):
                continue
            if not _looks_decoded_text(decoded):
                continue
            if raw != decoded:
                slice_blob[item.file_offset : item.end_offset] = decoded
                applied += 1
            continue

        decoded = bytes(b ^ item.key for b in raw)
        if not _looks_decoded_text(decoded):
            continue
        slice_blob[item.file_offset : item.end_offset] = decoded
        applied += 1
    return applied


def _patch_runtime_xor_keys_x86(
    slice_blob: memoryview,
    candidates: list[RuntimeStringCandidate],
) -> int:
    patched = 0
    seen: set[int] = set()
    for item in candidates:
        imm_off = item.imm_patch_offset
        if imm_off is None or imm_off in seen:
            continue
        seen.add(imm_off)
        if imm_off < 0 or imm_off >= len(slice_blob):
            continue
        if slice_blob[imm_off] == item.key:
            slice_blob[imm_off] = 0
            patched += 1
    return patched


def _patch_runtime_xor_keys_arm64(
    slice_blob: memoryview,
    candidates: list[RuntimeStringCandidate],
) -> int:
    patched = 0
    seen: set[int] = set()
    for item in candidates:
        imm_off = item.imm_patch_offset
        if imm_off is None or imm_off in seen:
            continue
        seen.add(imm_off)
        if imm_off < 0 or imm_off + 4 > len(slice_blob):
            continue
        insn = struct.unpack_from("<I", slice_blob, imm_off)[0]
        mov_info = _arm64_decode_mov_imm_w(insn)
        if mov_info is None:
            continue
        rd, _value = mov_info
        patched_insn = 0x52800000 | rd  # MOVZ Wd, #0
        if insn != patched_insn:
            struct.pack_into("<I", slice_blob, imm_off, patched_insn)
            patched += 1
    return patched


def _patch_x86_helper_return_ptr(
    slice_blob: memoryview,
    helper_addr: int,
    target_ptr: int,
) -> bool:
    helper_off = helper_addr
    patch = b"\x48\xb8" + struct.pack("<Q", target_ptr) + b"\xc3"  # movabs rax, imm64; ret
    if helper_off < 0 or helper_off + len(patch) > len(slice_blob):
        return False

    old = bytes(slice_blob[helper_off : helper_off + len(patch)])
    if old == patch:
        return False

    # Guard against patching non-function bytes when helper inference is noisy.
    probe_end = min(len(slice_blob), helper_off + 0x80)
    body = bytes(slice_blob[helper_off:probe_end])
    if b"\xC3" not in body and b"\xC2" not in body:
        return False

    slice_blob[helper_off : helper_off + len(patch)] = patch
    return True


def _file_offset_to_va(meta: ParsedSliceMeta, file_off: int) -> int | None:
    for seg in meta.segments:
        if seg.filesize <= 0:
            continue
        seg_start = seg.fileoff
        seg_end = seg.fileoff + seg.filesize
        if seg_start <= file_off < seg_end:
            return seg.vmaddr + (file_off - seg.fileoff)
    return None


def _find_arm64_text_slot(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
    text: str,
    used_offsets: list[tuple[int, int]],
) -> tuple[int, int, int] | None:
    try:
        plain = text.encode("utf-8", "replace") + b"\x00"
    except Exception:
        return None
    if len(plain) < 4:
        return None

    def overlaps(start: int, end: int) -> bool:
        for a, b in used_offsets:
            if not (end <= a or start >= b):
                return True
        return False

    sections: list[tuple[int, SectionInfo]] = []
    for section in meta.sections:
        if section.size <= 0:
            continue
        sec_start = section.offset
        sec_end = section.offset + section.size
        if sec_start < 0 or sec_end > len(slice_blob):
            continue
        if section.seg_maxprot & VM_PROT_EXECUTE:
            continue
        secname = section.sectname.lower()
        score = 20
        if (section.flags & SECTION_TYPE) == S_CSTRING_LITERALS or "cstring" in secname:
            score = 0
        elif "const" in secname:
            score = 5
        elif "data" in secname:
            score = 10
        sections.append((score, section))
    sections.sort(key=lambda item: (item[0], item[1].offset))

    # Prefer true encoded slots first (key != 0), then already-plain strings.
    key_order = list(range(1, 256)) + [0]
    for _score, section in sections:
        sec_start = section.offset
        sec_end = section.offset + section.size
        sec_blob = bytes(slice_blob[sec_start:sec_end])
        for key in key_order:
            encoded = bytes((b ^ key) & 0xFF for b in plain)
            idx = sec_blob.find(encoded)
            while idx != -1:
                file_off = sec_start + idx
                file_end = file_off + len(plain)
                if not overlaps(file_off, file_end):
                    va = _file_offset_to_va(meta, file_off)
                    if va is not None:
                        return file_off, va, key
                idx = sec_blob.find(encoded, idx + 1)
    return None


def _collect_arm64_pool_ranges(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for seg in meta.segments:
        if seg.filesize <= 0:
            continue
        if seg.maxprot & VM_PROT_EXECUTE:
            continue
        if not (seg.maxprot & VM_PROT_WRITE):
            continue

        seg_start = seg.fileoff
        seg_end = seg.fileoff + seg.filesize
        if seg_start < 0 or seg_end > len(slice_blob) or seg_start >= seg_end:
            continue

        covered: list[tuple[int, int]] = []
        for sec in meta.sections:
            if sec.size <= 0:
                continue
            sec_start = sec.offset
            sec_end = sec.offset + sec.size
            if sec_start < seg_start or sec_end > seg_end:
                continue
            covered.append((sec_start, sec_end))
        covered.sort()

        cur = seg_start
        for a, b in covered:
            if a > cur:
                chunk = bytes(slice_blob[cur:a])
                if chunk and all(v == 0 for v in chunk):
                    ranges.append((cur, a))
            cur = max(cur, b)
        if cur < seg_end:
            chunk = bytes(slice_blob[cur:seg_end])
            if chunk and all(v == 0 for v in chunk):
                ranges.append((cur, seg_end))
    return ranges


def _alloc_arm64_text_from_pool(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
    text: str,
    pool_state: list[list[int]],
) -> tuple[int, int] | None:
    plain = text.encode("utf-8", "replace") + b"\x00"
    if len(plain) < 4:
        return None
    for item in pool_state:
        cursor, end = item
        if cursor + len(plain) > end:
            continue
        start = cursor
        stop = start + len(plain)
        if any(v != 0 for v in slice_blob[start:stop]):
            continue
        slice_blob[start:stop] = plain
        item[0] = stop
        va = _file_offset_to_va(meta, start)
        if va is None:
            continue
        return start, va
    return None


def _encode_arm64_movz(rd: int, imm16: int, shift: int) -> int:
    hw = (shift // 16) & 0x3
    return 0xD2800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)


def _encode_arm64_movk(rd: int, imm16: int, shift: int) -> int:
    hw = (shift // 16) & 0x3
    return 0xF2800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)


def _patch_arm64_helper_return_ptr(
    slice_blob: memoryview,
    helper_addr: int,
    target_ptr: int,
) -> bool:
    helper_off = helper_addr
    if helper_off < 0 or helper_off + 20 > len(slice_blob):
        return False

    tail = struct.unpack_from("<I", slice_blob, helper_off + 16)[0]
    if tail != 0xD65F03C0:  # RET
        return False

    words = [
        _encode_arm64_movz(0, target_ptr & 0xFFFF, 0),
        _encode_arm64_movk(0, (target_ptr >> 16) & 0xFFFF, 16),
        _encode_arm64_movk(0, (target_ptr >> 32) & 0xFFFF, 32),
        _encode_arm64_movk(0, (target_ptr >> 48) & 0xFFFF, 48),
        0xD65F03C0,
    ]
    patch = struct.pack("<IIIII", *words)
    old = bytes(slice_blob[helper_off : helper_off + 20])
    if old == patch:
        return False
    slice_blob[helper_off : helper_off + 20] = patch
    return True


def _apply_arm64_runtime_helper_runnable_layer(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
    helper_literals: list[tuple[int, str]],
    runtime_candidates: list[RuntimeStringCandidate],
) -> tuple[int, int]:
    if not helper_literals:
        return 0, 0

    pool_state = [[start, end] for start, end in _collect_arm64_pool_ranges(slice_blob, meta)]
    text_to_slot: dict[str, tuple[int, int]] = {}
    used_offsets: list[tuple[int, int]] = []
    for item in runtime_candidates:
        if item.key != 0:
            continue
        va = _file_offset_to_va(meta, item.file_offset)
        if va is None:
            continue
        text_to_slot.setdefault(item.decoded, (item.file_offset, va))
        used_offsets.append((item.file_offset, item.end_offset))

    slot_patches = 0
    helper_patches = 0
    logged_misses = 0
    for helper_addr, text in helper_literals:
        if not text:
            continue

        slot = text_to_slot.get(text)
        if slot is None:
            found = _find_arm64_text_slot(slice_blob, meta, text, used_offsets)
            if found is not None:
                file_off, va, key = found
                plain = text.encode("utf-8", "replace") + b"\x00"
                cur = bytes(slice_blob[file_off : file_off + len(plain)])
                decoded = bytes((b ^ key) & 0xFF for b in cur)
                if decoded == plain and cur != plain:
                    slice_blob[file_off : file_off + len(plain)] = plain
                    slot_patches += 1
                elif key == 0:
                    # Slot is already plain, no data-side patch needed.
                    pass
                else:
                    continue
                text_to_slot[text] = (file_off, va)
                used_offsets.append((file_off, file_off + len(plain)))
                slot = (file_off, va)
            else:
                allocated = _alloc_arm64_text_from_pool(slice_blob, meta, text, pool_state)
                if allocated is None:
                    if VERBOSE and logged_misses < 12:
                        logged_misses += 1
                        _vlog(
                            f"arm64 runnable: unable to place text for helper 0x{helper_addr:x}: {text!r}"
                        )
                    continue
                file_off, va = allocated
                text_to_slot[text] = (file_off, va)
                used_offsets.append((file_off, file_off + len(text.encode("utf-8", "replace")) + 1))
                slot_patches += 1
                slot = (file_off, va)

        _off, slot_va = slot
        if _patch_arm64_helper_return_ptr(slice_blob, helper_addr, slot_va):
            helper_patches += 1

    return slot_patches, helper_patches


def _apply_x86_runtime_helper_runnable_layer(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
    helper_literals: list[tuple[int, str]],
    runtime_candidates: list[RuntimeStringCandidate],
) -> tuple[int, int]:
    if not helper_literals:
        return 0, 0

    pool_state = [[start, end] for start, end in _collect_arm64_pool_ranges(slice_blob, meta)]
    text_to_slot: dict[str, tuple[int, int]] = {}
    used_offsets: list[tuple[int, int]] = []
    for item in runtime_candidates:
        if item.key != 0:
            continue
        va = _file_offset_to_va(meta, item.file_offset)
        if va is None:
            continue
        text_to_slot.setdefault(item.decoded, (item.file_offset, va))
        used_offsets.append((item.file_offset, item.end_offset))

    slot_patches = 0
    helper_patches = 0
    logged_misses = 0
    for helper_addr, text in helper_literals:
        if not text:
            continue

        slot = text_to_slot.get(text)
        if slot is None:
            found = _find_arm64_text_slot(slice_blob, meta, text, used_offsets)
            if found is not None:
                file_off, va, key = found
                plain = text.encode("utf-8", "replace") + b"\x00"
                cur = bytes(slice_blob[file_off : file_off + len(plain)])
                decoded = bytes((b ^ key) & 0xFF for b in cur)
                if decoded == plain and cur != plain:
                    slice_blob[file_off : file_off + len(plain)] = plain
                    slot_patches += 1
                elif key == 0:
                    pass
                else:
                    continue
                text_to_slot[text] = (file_off, va)
                used_offsets.append((file_off, file_off + len(plain)))
                slot = (file_off, va)
            else:
                allocated = _alloc_arm64_text_from_pool(slice_blob, meta, text, pool_state)
                if allocated is None:
                    if VERBOSE and logged_misses < 12:
                        logged_misses += 1
                        _vlog(
                            f"x86 runnable: unable to place text for helper 0x{helper_addr:x}: {text!r}"
                        )
                    continue
                file_off, va = allocated
                text_to_slot[text] = (file_off, va)
                used_offsets.append((file_off, file_off + len(text.encode("utf-8", "replace")) + 1))
                slot_patches += 1
                slot = (file_off, va)

        _off, slot_va = slot
        if _patch_x86_helper_return_ptr(slice_blob, helper_addr, slot_va):
            helper_patches += 1

    return slot_patches, helper_patches


def _run_dynamic_emulation(
    slice_blob: memoryview,
    arch: str,
    load_method: int,
    mprotect_stub: int | None,
    dyld_stub: int | None,
    stub_name_by_addr: dict[int, str] | None,
    ptr_name_by_addr: dict[int, str] | None,
    timeout_ms: int,
    max_insn: int,
    arm64_enable_early_stop: bool = True,
) -> tuple[
    bytes,
    int | None,
    int | None,
    str,
    list[str],
    list[RuntimeStringCandidate],
    list[tuple[int, str]],
]:
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
        import unicorn.arm64_const as arm64_const
        from unicorn.arm64_const import (
            UC_ARM64_REG_PC,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
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
    if stub_name_by_addr is None:
        stub_name_by_addr = {}
    if ptr_name_by_addr is None:
        ptr_name_by_addr = {}

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
    heap_cursor = HEAP_ADDRESS
    heap_end = HEAP_ADDRESS + HEAP_SIZE
    arm64_thread_return_sentinel: int | None = None
    arm64_thread_stack_top: int | None = None
    arm64_thread_stack_floor: int | None = None
    arm64_thread_stack_slot_size = 0
    if arch == "arm64":
        uc.mem_map(HEAP_ADDRESS, HEAP_SIZE)
        uc.mem_map(STACK_ADDRESS_ARM64_THREAD, STACK_SIZE)
        arm64_thread_stack_top = STACK_ADDRESS_ARM64_THREAD + STACK_SIZE - PAGE_SIZE
        arm64_thread_stack_floor = STACK_ADDRESS_ARM64_THREAD + PAGE_SIZE
        # Synchronous pthread_create emulation may nest; allocate one dedicated
        # stack window per depth instead of reusing a single SP.
        arm64_thread_stack_slot_size = 0x40000
        arm64_thread_return_sentinel = THREAD_TRAMPOLINE_ADDRESS
        uc.mem_map(arm64_thread_return_sentinel, PAGE_SIZE)
        # RET (for safety); hook_code intercepts this address before execution.
        uc.mem_write(arm64_thread_return_sentinel, b"\xC0\x03\x5F\xD6")

    stack_ptr = stack_address + STACK_SIZE - PAGE_SIZE
    if arch == "x86_64":
        uc.reg_write(UC_X86_REG_RSP, stack_ptr)
        uc.reg_write(UC_X86_REG_RBP, stack_ptr)
        uc.mem_write(stack_ptr, int(CODE_ADDRESS + code_size).to_bytes(8, "little"))
    elif arch == "arm64":
        uc.reg_write(UC_ARM64_REG_SP, stack_ptr)
        uc.reg_write(UC_ARM64_REG_X29, stack_ptr)
        if arm64_thread_return_sentinel is not None:
            uc.reg_write(UC_ARM64_REG_X30, arm64_thread_return_sentinel)
        else:
            # Fallback should still stay inside mapped code range.
            uc.reg_write(UC_ARM64_REG_X30, CODE_ADDRESS + load_method)
    else:
        raise DeobfuscationError(f"dynamic mode unsupported arch: {arch}")

    arm64_reg_x_ids: list[int] = []
    if arch == "arm64":
        arm64_reg_x_ids = [getattr(arm64_const, f"UC_ARM64_REG_X{i}") for i in range(31)]

    write_min: int | None = None
    write_max: int | None = None
    unresolved_branch_skips = 0
    unresolved_branch_logs = 0
    auto_mapped_pages: set[int] = set()
    auto_map_logs = 0
    executed_insn = 0
    stub_hit_counts: dict[str, int] = {}
    helper_infer_fail_logs = 0
    observed_runtime_strings: list[str] = []
    observed_runtime_string_set: set[str] = set()
    observed_runtime_candidates: dict[int, RuntimeStringCandidate] = {}
    observed_x86_helper_literals: dict[int, str] = {}
    observed_arm64_helper_literals: dict[int, str] = {}
    arm64_active_str_streams: dict[int, tuple[int, bytearray]] = {}
    arm64_thread_frames: list[dict[str, object]] = []
    arm64_thread_launches = 0
    arm64_thread_launch_logs = 0
    arm64_last_progress_insn = 0
    arm64_early_stop_reason: str | None = None
    arm64_idle_window_insn = 4_000_000
    arm64_min_runtime_strings_for_early_stop = 16
    arm64_min_helper_literals_for_early_stop = 12
    x86_rel_call_seen = 0
    x86_indirect_call_seen = 0
    x86_callsite_string_seen = 0

    def _record_runtime_string_text(data: bytes) -> str | None:
        nonlocal arm64_last_progress_insn
        if len(data) < 6:
            return None
        if len(data) > 256:
            return None
        if not _looks_decoded_text(data):
            return None
        text = data.decode("ascii", "replace")
        if text in observed_runtime_string_set:
            return text
        observed_runtime_string_set.add(text)
        observed_runtime_strings.append(text)
        arm64_last_progress_insn = executed_insn
        return text

    def _observe_runtime_cstring_ptr(ptr: int) -> str | None:
        if ptr <= 0:
            return None

        max_len = 256
        collected = bytearray()
        for idx in range(max_len):
            try:
                byte_val = uc.mem_read(ptr + idx, 1)[0]
            except Exception:
                return None
            if byte_val == 0:
                break
            collected.append(byte_val)
        if not collected:
            return None

        data = bytes(collected)
        text = _record_runtime_string_text(data)
        if text is None:
            return None

        if CODE_ADDRESS <= ptr < CODE_ADDRESS + len(slice_blob):
            file_offset = ptr - CODE_ADDRESS
            end_offset = file_offset + len(data)
            if 0 <= file_offset < end_offset <= len(slice_blob):
                prev = observed_runtime_candidates.get(file_offset)
                candidate = RuntimeStringCandidate(
                    file_offset=file_offset,
                    end_offset=end_offset,
                    key=0,
                    decoded=text,
                    imm_patch_offset=None,
                )
                if prev is None or (end_offset - file_offset) > (prev.end_offset - prev.file_offset):
                    observed_runtime_candidates[file_offset] = candidate
        return text

    def _decode_x86_call_target(call_addr: int) -> int | None:
        if call_addr < CODE_ADDRESS or call_addr + 5 > CODE_ADDRESS + len(slice_blob):
            return None
        try:
            insn = bytes(uc.mem_read(call_addr, 5))
        except Exception:
            return None
        if len(insn) != 5 or insn[0] != 0xE8:
            return None
        disp = struct.unpack_from("<i", insn, 1)[0]
        target = (call_addr + 5 + disp) & 0xFFFFFFFFFFFFFFFF
        if not (CODE_ADDRESS <= target < CODE_ADDRESS + len(slice_blob)):
            return None
        return target

    def _decode_x86_rip_mem_call_ptr(call_addr: int) -> int | None:
        if call_addr < CODE_ADDRESS or call_addr + 6 > CODE_ADDRESS + len(slice_blob):
            return None
        try:
            insn = bytes(uc.mem_read(call_addr, 6))
        except Exception:
            return None
        if len(insn) != 6 or insn[0] != 0xFF or insn[1] != 0x15:
            return None
        disp = struct.unpack_from("<i", insn, 2)[0]
        ptr_addr = (call_addr + 6 + disp) & 0xFFFFFFFFFFFFFFFF
        if not (CODE_ADDRESS <= ptr_addr < CODE_ADDRESS + len(slice_blob)):
            return None
        return ptr_addr

    def _infer_x86_literal_helper_for_callsite(callsite: int, stub_addr: int) -> int | None:
        if callsite < CODE_ADDRESS or callsite >= CODE_ADDRESS + len(slice_blob):
            return None

        for back in (5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60):
            call_addr = callsite - back
            target = _decode_x86_call_target(call_addr)
            if target is None:
                continue
            if target == stub_addr:
                continue
            target_off = target - CODE_ADDRESS
            if target_off in stub_name_by_addr:
                continue
            return target_off
        return None

    def _infer_x86_literal_helper_for_stub(stub_addr: int) -> int | None:
        try:
            rsp = uc.reg_read(UC_X86_REG_RSP)
            ret_addr = int.from_bytes(uc.mem_read(rsp, 8), "little")
        except Exception:
            return None
        return _infer_x86_literal_helper_for_callsite(ret_addr - 5, stub_addr)

    def _decode_arm64_bl_target(insn_addr: int) -> int | None:
        if insn_addr < CODE_ADDRESS or insn_addr + 4 > CODE_ADDRESS + len(slice_blob):
            return None
        try:
            insn_word = int.from_bytes(uc.mem_read(insn_addr, 4), "little")
        except Exception:
            return None
        if (insn_word & 0xFC000000) != 0x94000000:
            return None
        imm26 = insn_word & 0x03FFFFFF
        disp = _sign_extend(imm26, 26) << 2
        target = (insn_addr + disp) & 0xFFFFFFFFFFFFFFFF
        if not (CODE_ADDRESS <= target < CODE_ADDRESS + len(slice_blob)):
            return None
        return target

    def _infer_arm64_literal_helper_for_stub(stub_addr: int) -> int | None:
        try:
            lr = uc.reg_read(UC_ARM64_REG_X30)
        except Exception:
            return None
        callsite = lr - 4
        if callsite < CODE_ADDRESS or callsite >= CODE_ADDRESS + len(slice_blob):
            return None

        # Typical pattern:
        #   BL sub_xxxx    ; literal helper
        #   BL _sel_registerName/_objc_getClass
        for back in (4, 8, 12, 16, 20):
            bl_addr = callsite - back
            target = _decode_arm64_bl_target(bl_addr)
            if target is None:
                continue
            if target == stub_addr:
                continue
            if (target - CODE_ADDRESS) in stub_name_by_addr:
                continue
            return target
        return None

    def _arm64_feed_written_bytes(base_addr: int, data_bytes: bytes) -> None:
        # Track sequential byte writes and harvest ASCII C-strings when a 0-byte
        # terminator is observed. This captures transient runtime decode output
        # even when memory is later re-obfuscated.
        for idx, cur in enumerate(data_bytes):
            addr = base_addr + idx
            seq = arm64_active_str_streams.pop(addr, None)
            if seq is None:
                if 32 <= cur <= 126:
                    arm64_active_str_streams[addr + 1] = (addr, bytearray([cur]))
                continue

            start_addr, buf = seq
            if cur == 0:
                _record_runtime_string_text(bytes(buf))
                continue

            if 32 <= cur <= 126 and len(buf) < 256:
                buf.append(cur)
                arm64_active_str_streams[addr + 1] = (start_addr, buf)
            elif 32 <= cur <= 126:
                arm64_active_str_streams[addr + 1] = (addr, bytearray([cur]))

        if len(arm64_active_str_streams) > 8192:
            arm64_active_str_streams.clear()

    def hook_write(_uc, access, address, size, value, _user_data):
        nonlocal write_min, write_max, arm64_last_progress_insn
        if access != UC_MEM_WRITE:
            return
        if CODE_ADDRESS <= address < CODE_ADDRESS + code_size:
            local_min = address - CODE_ADDRESS
            local_max = local_min + max(size, 1) - 1
            if write_min is None or local_min < write_min:
                write_min = local_min
                arm64_last_progress_insn = executed_insn
            if write_max is None or local_max > write_max:
                write_max = local_max
                arm64_last_progress_insn = executed_insn
        if arch == "arm64" and size > 0 and size <= 8:
            # Unicorn reports integer "value" for memory write hooks.
            # Convert to little-endian bytes matching actual memory layout.
            try:
                data_bytes = int(value).to_bytes(size, "little", signed=False)
            except Exception:
                data_bytes = b""
            if data_bytes:
                _arm64_feed_written_bytes(address, data_bytes)

    def _x64_force_return(retval: int) -> None:
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = int.from_bytes(uc.mem_read(rsp, 8), "little")
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RAX, retval)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)

    def _arm64_force_return(retval: int, current_pc: int) -> None:
        lr = uc.reg_read(UC_ARM64_REG_X30)
        if not (CODE_ADDRESS <= lr < CODE_ADDRESS + code_size):
            lr = current_pc + 4
        uc.reg_write(UC_ARM64_REG_X0, retval)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def _arm64_return_preserve_x0(current_pc: int) -> None:
        lr = uc.reg_read(UC_ARM64_REG_X30)
        if not (CODE_ADDRESS <= lr < CODE_ADDRESS + code_size):
            lr = current_pc + 4
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def _arm64_alloc(size_hint: int) -> int:
        nonlocal heap_cursor
        try:
            wanted = int(size_hint)
        except Exception:
            wanted = 0
        if wanted <= 0:
            wanted = 0x100
        wanted = _align_up(wanted, 0x10)
        if heap_cursor + wanted > heap_end:
            return 0
        ptr = heap_cursor
        heap_cursor += wanted
        return ptr

    def _arm64_thread_sp_for_depth(depth: int) -> int | None:
        if (
            arm64_thread_stack_top is None
            or arm64_thread_stack_floor is None
            or arm64_thread_stack_slot_size <= 0
        ):
            return None
        if depth <= 0:
            depth = 1
        sp = arm64_thread_stack_top - (depth - 1) * arm64_thread_stack_slot_size
        if sp <= arm64_thread_stack_floor:
            return None
        return sp

    def _arm64_bzero(ptr: int, size: int) -> None:
        if ptr <= 0:
            return
        try:
            count = int(size)
        except Exception:
            count = 0
        if count <= 0:
            return
        count = min(count, 0x100000)
        try:
            uc.mem_write(ptr, b"\x00" * count)
        except Exception:
            return

    def _arm64_memcpy(dst: int, src: int, size: int) -> None:
        if dst <= 0 or src <= 0:
            return
        try:
            count = int(size)
        except Exception:
            count = 0
        if count <= 0:
            return
        count = min(count, 0x100000)
        try:
            data = bytes(uc.mem_read(src, count))
        except Exception:
            return
        try:
            uc.mem_write(dst, data)
        except Exception:
            return

    def _arm64_write_cstr(dst: int, text: str, max_size: int) -> int:
        if dst <= 0:
            return 0
        try:
            limit = int(max_size)
        except Exception:
            limit = 0
        if limit <= 0:
            return 0
        raw = text.encode("utf-8", "replace") + b"\x00"
        to_write = raw[:limit]
        if not to_write:
            return 0
        try:
            uc.mem_write(dst, to_write)
        except Exception:
            return 0
        if to_write[-1] == 0:
            return max(len(to_write) - 1, 0)
        return len(to_write)

    def _arm64_resume_parent_from_thread() -> bool:
        if not arm64_thread_frames:
            return False
        frame = arm64_thread_frames.pop()
        regs = frame.get("regs")
        if isinstance(regs, list) and len(regs) == len(arm64_reg_x_ids):
            for reg_id, value in zip(arm64_reg_x_ids, regs):
                try:
                    uc.reg_write(reg_id, int(value))
                except Exception:
                    pass

        parent_sp = frame.get("sp")
        if isinstance(parent_sp, int):
            uc.reg_write(UC_ARM64_REG_SP, parent_sp)
            uc.reg_write(UC_ARM64_REG_X29, parent_sp)

        resume_pc = frame.get("resume_pc")
        if not isinstance(resume_pc, int):
            resume_pc = uc.reg_read(UC_ARM64_REG_X30)
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, resume_pc)
        return True

    def hook_code(_uc, address, _size, _user_data):
        nonlocal unresolved_branch_skips, unresolved_branch_logs, executed_insn
        nonlocal arm64_thread_launches, arm64_thread_launch_logs
        nonlocal arm64_early_stop_reason, arm64_last_progress_insn
        nonlocal x86_rel_call_seen, x86_indirect_call_seen, x86_callsite_string_seen
        executed_insn += 1
        if (
            arch == "arm64"
            and arm64_enable_early_stop
            and arm64_early_stop_reason is None
            and (executed_insn % 100000) == 0
            and arm64_thread_launches > 0
            and len(observed_runtime_string_set) >= arm64_min_runtime_strings_for_early_stop
            and len(observed_arm64_helper_literals) >= arm64_min_helper_literals_for_early_stop
            and (executed_insn - arm64_last_progress_insn) >= arm64_idle_window_insn
        ):
            arm64_early_stop_reason = (
                f"stable_runtime idle={arm64_idle_window_insn} "
                f"strings={len(observed_runtime_string_set)} "
                f"helpers={len(observed_arm64_helper_literals)}"
            )
            _vlog(f"dynamic: arm64 early stop: {arm64_early_stop_reason}")
            uc.emu_stop()
            return
        if address == CODE_ADDRESS and load_method != 0:
            _vlog("dynamic: execution reached image base; stopping emulation")
            uc.emu_stop()
            return
        if mprotect_stub is not None and address == CODE_ADDRESS + mprotect_stub:
            if arch == "x86_64":
                _ = uc.reg_read(UC_X86_REG_RDI)
                _ = uc.reg_read(UC_X86_REG_RSI)
                _ = uc.reg_read(UC_X86_REG_RDX)
                _x64_force_return(0)
            elif arch == "arm64":
                _ = uc.reg_read(UC_ARM64_REG_X0)
                _ = uc.reg_read(UC_ARM64_REG_X1)
                _ = uc.reg_read(UC_ARM64_REG_X2)
                _arm64_force_return(0, address)
            else:
                raise DeobfuscationError(f"dynamic mode unsupported arch: {arch}")
            return

        if dyld_stub is not None and address == CODE_ADDRESS + dyld_stub:
            if arch == "x86_64":
                _ = uc.reg_read(UC_X86_REG_RDI)
                _x64_force_return(1)
            elif arch == "arm64":
                _ = uc.reg_read(UC_ARM64_REG_X0)
                _arm64_force_return(1, address)
            else:
                raise DeobfuscationError(f"dynamic mode unsupported arch: {arch}")

        if arch == "x86_64":
            call_target = _decode_x86_call_target(address)
            call_ptr = _decode_x86_rip_mem_call_ptr(address)
            if call_target is not None:
                x86_rel_call_seen += 1
            if call_ptr is not None:
                x86_indirect_call_seen += 1
            stub_name = None
            helper_target = None
            if call_target is not None:
                stub_off = call_target - CODE_ADDRESS
                stub_name = stub_name_by_addr.get(stub_off)
                helper_target = call_target
            elif call_ptr is not None:
                stub_name = ptr_name_by_addr.get(call_ptr)
                helper_target = call_ptr

            track_helper_literal = stub_name in {"_objc_getClass", "_sel_registerName"}
            # Fallback for stripped x86 symbols: if this is an indirect external-style
            # call and RDI already points at a decoded C-string, still try to bind the
            # preceding helper to that text.
            if (
                not track_helper_literal
                and call_ptr is not None
                and helper_target is not None
            ):
                track_helper_literal = True

            if stub_name in {"_objc_getClass", "_objc_getMetaClass", "_sel_registerName", "_getenv"}:
                _observe_runtime_cstring_ptr(uc.reg_read(UC_X86_REG_RDI))

            if track_helper_literal:
                text = _observe_runtime_cstring_ptr(uc.reg_read(UC_X86_REG_RDI))
                if text and helper_target is not None:
                    x86_callsite_string_seen += 1
                    helper_off = _infer_x86_literal_helper_for_callsite(address, helper_target)
                    if helper_off is not None:
                        prev = observed_x86_helper_literals.get(helper_off)
                        if prev is None:
                            observed_x86_helper_literals[helper_off] = text
                        elif prev != text and len(text) > len(prev):
                            observed_x86_helper_literals[helper_off] = text
                    elif VERBOSE and helper_infer_fail_logs < 12:
                        helper_infer_fail_logs += 1
                        _vlog(
                            f"dynamic: x86 helper infer miss for {stub_name} at "
                            f"0x{address - CODE_ADDRESS:x}"
                        )
            elif stub_name in {"_strcmp", "_strstr"}:
                _observe_runtime_cstring_ptr(uc.reg_read(UC_X86_REG_RDI))
                _observe_runtime_cstring_ptr(uc.reg_read(UC_X86_REG_RSI))

        if arch == "x86_64":
            stub_name = stub_name_by_addr.get(address - CODE_ADDRESS)
            if stub_name is not None:
                stub_hit_counts[stub_name] = stub_hit_counts.get(stub_name, 0) + 1
                if stub_name in {"_objc_getClass", "_objc_getMetaClass", "_sel_registerName", "_getenv"}:
                    text = _observe_runtime_cstring_ptr(uc.reg_read(UC_X86_REG_RDI))
                    if text and stub_name in {"_objc_getClass", "_sel_registerName"}:
                        helper_off = _infer_x86_literal_helper_for_stub(address)
                        if helper_off is not None:
                            prev = observed_x86_helper_literals.get(helper_off)
                            if prev is None:
                                observed_x86_helper_literals[helper_off] = text
                            elif prev != text and len(text) > len(prev):
                                observed_x86_helper_literals[helper_off] = text
                        elif VERBOSE and helper_infer_fail_logs < 12:
                            helper_infer_fail_logs += 1
                            try:
                                rsp_dbg = uc.reg_read(UC_X86_REG_RSP)
                                ret_dbg = int.from_bytes(uc.mem_read(rsp_dbg, 8), "little")
                                call_dbg = ret_dbg - 5
                            except Exception:
                                ret_dbg = 0
                                call_dbg = 0
                            _vlog(
                                f"dynamic: x86 helper infer miss for {stub_name} at "
                                f"0x{address - CODE_ADDRESS:x} ret=0x{ret_dbg - CODE_ADDRESS:x} "
                                f"callsite=0x{call_dbg - CODE_ADDRESS:x}"
                            )
                elif stub_name in {"_strcmp", "_strstr"}:
                    _observe_runtime_cstring_ptr(uc.reg_read(UC_X86_REG_RDI))
                    _observe_runtime_cstring_ptr(uc.reg_read(UC_X86_REG_RSI))

                if stub_name in {"_objc_getClass", "_objc_getMetaClass", "_sel_registerName"}:
                    _x64_force_return(1)
                    return
                if stub_name in {"_memcmp", "_strcmp"}:
                    _x64_force_return(0)
                    return
                if stub_name == "_strstr":
                    _x64_force_return(uc.reg_read(UC_X86_REG_RDI))
                    return

        if arch == "arm64":
            if (
                arm64_thread_return_sentinel is not None
                and address == arm64_thread_return_sentinel
            ):
                if _arm64_resume_parent_from_thread():
                    return
                _vlog("dynamic: arm64 thread sentinel hit without parent frame; stopping emulation")
                uc.emu_stop()
                return

            stub_name = stub_name_by_addr.get(address - CODE_ADDRESS)
            if stub_name is not None:
                stub_hit_counts[stub_name] = stub_hit_counts.get(stub_name, 0) + 1
                if stub_name in {"_objc_getClass", "_objc_getMetaClass", "_sel_registerName", "_getenv"}:
                    text = _observe_runtime_cstring_ptr(uc.reg_read(UC_ARM64_REG_X0))
                    if text and stub_name in {"_objc_getClass", "_sel_registerName"}:
                        helper_addr = _infer_arm64_literal_helper_for_stub(address)
                        if helper_addr is not None:
                            prev = observed_arm64_helper_literals.get(helper_addr)
                            if prev is None:
                                observed_arm64_helper_literals[helper_addr] = text
                                arm64_last_progress_insn = executed_insn
                            elif prev != text and len(text) > len(prev):
                                observed_arm64_helper_literals[helper_addr] = text
                                arm64_last_progress_insn = executed_insn
                        elif VERBOSE and helper_infer_fail_logs < 12:
                            helper_infer_fail_logs += 1
                            try:
                                lr_dbg = uc.reg_read(UC_ARM64_REG_X30)
                                callsite_dbg = lr_dbg - 4
                            except Exception:
                                lr_dbg = 0
                                callsite_dbg = 0
                            _vlog(
                                f"dynamic: arm64 helper infer miss for {stub_name} at "
                                f"0x{address - CODE_ADDRESS:x} lr=0x{lr_dbg - CODE_ADDRESS:x} "
                                f"callsite=0x{callsite_dbg - CODE_ADDRESS:x}"
                            )
                elif stub_name in {"_strcmp", "_strstr"}:
                    _observe_runtime_cstring_ptr(uc.reg_read(UC_ARM64_REG_X0))
                    _observe_runtime_cstring_ptr(uc.reg_read(UC_ARM64_REG_X1))

                if stub_name in {"___chkstk_darwin"}:
                    _arm64_return_preserve_x0(address)
                    return
                if stub_name in {"__Znwm", "__Znam", "_malloc"}:
                    size_hint = uc.reg_read(UC_ARM64_REG_X0)
                    _arm64_force_return(_arm64_alloc(size_hint), address)
                    return
                if stub_name in {"__ZdlPv", "__ZdaPv", "_free"}:
                    _arm64_return_preserve_x0(address)
                    return
                if stub_name in {"_bzero"}:
                    _arm64_bzero(uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1))
                    _arm64_return_preserve_x0(address)
                    return
                if stub_name in {"_memcpy", "_memmove"}:
                    dst = uc.reg_read(UC_ARM64_REG_X0)
                    src = uc.reg_read(UC_ARM64_REG_X1)
                    size = uc.reg_read(UC_ARM64_REG_X2)
                    _arm64_memcpy(dst, src, size)
                    _arm64_force_return(dst, address)
                    return
                if stub_name in {"_memcmp", "_strcmp"}:
                    _arm64_force_return(0, address)
                    return
                if stub_name == "_strstr":
                    _arm64_force_return(uc.reg_read(UC_ARM64_REG_X0), address)
                    return
                if stub_name in {"_mprotect", "_vm_protect"}:
                    _arm64_force_return(0, address)
                    return
                if stub_name in {"__dyld_get_image_vmaddr_slide", "__dyld_image_count"}:
                    _arm64_force_return(1, address)
                    return
                if stub_name in {"__dyld_get_image_header"}:
                    _arm64_force_return(CODE_ADDRESS, address)
                    return
                if stub_name in {"__dyld_register_func_for_add_image"}:
                    _arm64_return_preserve_x0(address)
                    return
                if stub_name in {"_objc_getClass", "_objc_getMetaClass", "_sel_registerName"}:
                    _arm64_force_return(1, address)
                    return
                if stub_name in {"_getppid"}:
                    _arm64_force_return(1, address)
                    return
                if stub_name in {"_proc_pidpath"}:
                    out_len = _arm64_write_cstr(
                        uc.reg_read(UC_ARM64_REG_X1),
                        "/Applications/Finder.app",
                        uc.reg_read(UC_ARM64_REG_X2),
                    )
                    _arm64_force_return(out_len, address)
                    return
                if stub_name in {"_pthread_create"}:
                    thread_ptr = uc.reg_read(UC_ARM64_REG_X0)
                    start_routine = uc.reg_read(UC_ARM64_REG_X2)
                    start_arg = uc.reg_read(UC_ARM64_REG_X3)
                    next_thread_sp = _arm64_thread_sp_for_depth(len(arm64_thread_frames) + 1)
                    if (
                        arm64_thread_return_sentinel is not None
                        and next_thread_sp is not None
                        and CODE_ADDRESS <= start_routine < CODE_ADDRESS + code_size
                        and len(arm64_thread_frames) < 32
                    ):
                        resume_pc = uc.reg_read(UC_ARM64_REG_X30)
                        parent_regs = [uc.reg_read(reg_id) for reg_id in arm64_reg_x_ids]
                        parent_sp = uc.reg_read(UC_ARM64_REG_SP)
                        arm64_thread_frames.append(
                            {"resume_pc": resume_pc, "sp": parent_sp, "regs": parent_regs}
                        )
                        arm64_thread_launches += 1
                        arm64_last_progress_insn = executed_insn
                        if VERBOSE and arm64_thread_launch_logs < 16:
                            arm64_thread_launch_logs += 1
                            _vlog(
                                f"dynamic: arm64 pthread_create start=0x{start_routine - CODE_ADDRESS:x} "
                                f"arg=0x{start_arg:x} resume=0x{resume_pc - CODE_ADDRESS:x}"
                            )
                        if thread_ptr > 0:
                            try:
                                uc.mem_write(
                                    thread_ptr,
                                    int(arm64_thread_launches).to_bytes(8, "little"),
                                )
                            except Exception:
                                pass
                        uc.reg_write(UC_ARM64_REG_SP, next_thread_sp)
                        uc.reg_write(UC_ARM64_REG_X29, next_thread_sp)
                        uc.reg_write(UC_ARM64_REG_X0, start_arg)
                        uc.reg_write(UC_ARM64_REG_X1, 0)
                        uc.reg_write(UC_ARM64_REG_X2, 0)
                        uc.reg_write(UC_ARM64_REG_X3, 0)
                        uc.reg_write(UC_ARM64_REG_X30, arm64_thread_return_sentinel)
                        uc.reg_write(UC_ARM64_REG_PC, start_routine)
                        return
                    if (
                        VERBOSE
                        and arm64_thread_return_sentinel is not None
                        and next_thread_sp is None
                    ):
                        _vlog(
                            "dynamic: arm64 pthread_create skipped (thread stack slots exhausted); "
                            "falling back to stub return"
                        )
                    _arm64_force_return(0, address)
                    return
                if stub_name in {"_snprintf", "_pthread_setspecific", "_usleep"}:
                    _arm64_force_return(0, address)
                    return
                if stub_name in {"_dladdr"}:
                    _arm64_force_return(0, address)
                    return
                if "throw_system_error" in stub_name:
                    if arm64_thread_frames and arm64_thread_return_sentinel is not None:
                        uc.reg_write(UC_ARM64_REG_PC, arm64_thread_return_sentinel)
                        return
                    _vlog("dynamic: arm64 throw_system_error encountered; stopping emulation")
                    uc.emu_stop()
                    return
                if stub_name in {"___stack_chk_fail", "_exit"}:
                    if arm64_thread_frames and arm64_thread_return_sentinel is not None:
                        uc.reg_write(UC_ARM64_REG_PC, arm64_thread_return_sentinel)
                        return
                    _arm64_force_return(0, address)
                    return
                _arm64_return_preserve_x0(address)
                return

            try:
                insn_word = int.from_bytes(uc.mem_read(address, 4), "little")
            except Exception:
                insn_word = 0

            br_kind = None
            if (insn_word & 0xFFFFFC1F) == 0xD63F0000:
                br_kind = "blr"
            elif (insn_word & 0xFFFFFC1F) == 0xD61F0000:
                br_kind = "br"
            elif (insn_word & 0xFFE0001F) == 0xD4200000:
                if arm64_thread_frames and arm64_thread_return_sentinel is not None:
                    uc.reg_write(UC_ARM64_REG_PC, arm64_thread_return_sentinel)
                    return
                _vlog(
                    f"dynamic: arm64 BRK at 0x{address - CODE_ADDRESS:x}; stopping emulation"
                )
                uc.emu_stop()
                return
            if br_kind is not None:
                reg_idx = (insn_word >> 5) & 0x1F
                target = 0
                if 0 <= reg_idx < len(arm64_reg_x_ids):
                    try:
                        target = uc.reg_read(arm64_reg_x_ids[reg_idx])
                    except Exception:
                        target = 0

                out_of_range = not (CODE_ADDRESS <= target < CODE_ADDRESS + code_size)
                if target == 0 or out_of_range:
                    unresolved_branch_skips += 1
                    if unresolved_branch_logs < 20:
                        unresolved_branch_logs += 1
                        _vlog(
                            f"dynamic: arm64 unresolved {br_kind} X{reg_idx} "
                            f"at 0x{address - CODE_ADDRESS:x} target=0x{target:x}; skipping"
                        )
                    if br_kind == "blr":
                        # Emulate "call then immediate return".
                        ret_site = address + 4
                        uc.reg_write(UC_ARM64_REG_X30, ret_site)
                        uc.reg_write(UC_ARM64_REG_PC, ret_site)
                    else:
                        _arm64_return_preserve_x0(address)
                    return

    def hook_unmapped(_uc, _type, address, size, _value, _user_data):
        nonlocal auto_map_logs
        # Some startup code touches runtime pointers/heap regions that are
        # unmapped in our minimal emulator context. Map pages on-demand so
        # decryption routines can continue.
        if size <= 0:
            size = 1
        map_start = address & ~(PAGE_SIZE - 1)
        map_end = _align_up(address + size, PAGE_SIZE)

        # Keep auto-mapping constrained to low canonical user-space range.
        if map_start < 0 or map_end > 0x1_0000_0000:
            return False

        mapped_any = False
        cur = map_start
        while cur < map_end:
            if cur not in auto_mapped_pages:
                try:
                    uc.mem_map(cur, PAGE_SIZE)
                except UcError:
                    return False
                auto_mapped_pages.add(cur)
                mapped_any = True
                if auto_map_logs < 20:
                    auto_map_logs += 1
                    _vlog(f"dynamic: auto-mapped page @ 0x{cur:x}")
            cur += PAGE_SIZE
        return mapped_any

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

    timeout_us = max(timeout_ms, 0) * 1000
    insn_count = max(max_insn, 0)
    start = CODE_ADDRESS + load_method
    emu_status = "OK"
    t0 = time.monotonic()
    try:
        uc.emu_start(start, CODE_ADDRESS + code_size, timeout=timeout_us, count=insn_count)
    except UcError as exc:
        # Some exceptions are expected after target code is dumped.
        emu_status = str(exc)
        pc = None
        insn_hex = None
        try:
            if arch == "x86_64":
                pc = uc.reg_read(UC_X86_REG_RIP)
                insn_hex = uc.mem_read(pc, 8).hex()
            elif arch == "arm64":
                pc = uc.reg_read(UC_ARM64_REG_PC)
                insn_hex = uc.mem_read(pc, 4).hex()
        except Exception:
            pc = None
            insn_hex = None
        if pc is not None:
            emu_status = (
                f"{emu_status} @pc=0x{pc - CODE_ADDRESS:x}"
                + (f" insn={insn_hex}" if insn_hex else "")
            )
        if unresolved_branch_skips:
            emu_status = f"{emu_status} unresolved_branches={unresolved_branch_skips}"
    else:
        elapsed_ms = (time.monotonic() - t0) * 1000.0
        if arm64_early_stop_reason:
            emu_status = f"STOP_EARLY({arm64_early_stop_reason})"
        elif insn_count > 0 and executed_insn >= insn_count:
            emu_status = f"STOP_MAX_INSN({insn_count})"
        elif timeout_ms > 0 and elapsed_ms >= timeout_ms * 0.98:
            emu_status = f"STOP_TIMEOUT({timeout_ms}ms)"
    if executed_insn:
        emu_status = f"{emu_status} insn_exec={executed_insn}"
    if arm64_thread_launches:
        emu_status = f"{emu_status} pthread_sync={arm64_thread_launches}"
    if VERBOSE and stub_hit_counts:
        top_stub_hits = sorted(stub_hit_counts.items(), key=lambda item: item[1], reverse=True)[:16]
        _vlog(
            f"dynamic: {arch} stub hit counts "
            + ", ".join(f"{name}={count}" for name, count in top_stub_hits)
        )
    if VERBOSE and arm64_thread_launches:
        _vlog(f"dynamic: arm64 pthread_create synchronous launches={arm64_thread_launches}")
    if VERBOSE and arch == "x86_64":
        _vlog(
            f"dynamic: x86 callsite stats rel={x86_rel_call_seen} "
            f"indirect={x86_indirect_call_seen} callsite_strings={x86_callsite_string_seen}"
        )
    if VERBOSE and observed_x86_helper_literals:
        _vlog(
            f"dynamic: x86 helper literal mappings={len(observed_x86_helper_literals)}"
        )
    if VERBOSE and observed_arm64_helper_literals:
        _vlog(
            f"dynamic: arm64 helper literal mappings={len(observed_arm64_helper_literals)}"
        )

    if len(observed_runtime_strings) > 128:
        observed_runtime_strings = observed_runtime_strings[:128]

    dumped = bytes(uc.mem_read(CODE_ADDRESS, len(slice_blob)))
    observed_runtime_string_candidates = sorted(
        observed_runtime_candidates.values(), key=lambda item: item.file_offset
    )
    if arch == "x86_64":
        observed_helper_literals = sorted(observed_x86_helper_literals.items(), key=lambda item: item[0])
    elif arch == "arm64":
        observed_helper_literals = sorted(observed_arm64_helper_literals.items(), key=lambda item: item[0])
    else:
        observed_helper_literals = []
    return (
        dumped,
        write_min,
        write_max,
        emu_status,
        observed_runtime_strings,
        observed_runtime_string_candidates,
        observed_helper_literals,
    )


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
    string_layer: str,
    xor_key_hint: int | None = None,
    arm64_enable_early_stop: bool = True,
    analysis_seed_blob: bytes | None = None,
) -> DynamicSliceResult:
    header = _parse_macho_header_64(slice_blob)
    if _cpu_to_arch(header.cputype) != slice_info.arch:
        raise DeobfuscationError(
            f"slice CPU type mismatch in {slice_info.source} ({slice_info.arch})"
        )
    _vlog(
        f"{slice_info.source}: dynamic patch start arch={slice_info.arch} "
        f"slice_off=0x{slice_info.offset:x} slice_size=0x{slice_info.size:x} "
        f"timeout_ms={timeout_ms} max_insn={max_insn} "
        f"arm64_early_stop={'on' if arm64_enable_early_stop else 'off'}"
    )

    meta = _parse_slice_meta(slice_blob, header)
    fixed_symbol_strings = _restore_symbol_strings(slice_blob, header, meta)
    fixed_section_names = _restore_section_names(slice_blob, meta)

    effective_timeout_ms = timeout_ms
    effective_max_insn = max_insn
    if slice_info.arch == "arm64":
        if timeout_ms == DEFAULT_DYNAMIC_TIMEOUT_MS:
            effective_timeout_ms = 180000
            _vlog(
                f"{slice_info.source}: arm64 dynamic timeout auto-tuned to "
                f"{effective_timeout_ms}ms"
            )
        if max_insn == DEFAULT_DYNAMIC_MAX_INSN:
            effective_max_insn = 50000000
            _vlog(
                f"{slice_info.source}: arm64 dynamic max instructions auto-tuned to "
                f"{effective_max_insn}"
            )

    ptr_to_name = _parse_lazy_bind_symbol_map(slice_blob, meta, header=header)
    if not ptr_to_name:
        raise DeobfuscationError("failed to parse lazy bind information")
    mprotect_stub, dyld_stub, stub_name_by_addr, ptr_name_by_addr = _locate_required_stubs(
        slice_blob,
        meta,
        ptr_to_name,
        slice_info.arch,
        xor_key_hint=xor_key_hint,
    )
    if VERBOSE and slice_info.arch == "x86_64":
        sample = ", ".join(
            f"0x{off:x}:{name}" for off, name in list(stub_name_by_addr.items())[:12]
        )
        objc_sample = ", ".join(
            f"0x{off:x}:{name}"
            for off, name in stub_name_by_addr.items()
            if ("objc" in name or "sel_" in name or "getenv" in name)
        )
        _vlog(
            f"{slice_info.source}: x86 stub symbols discovered={len(stub_name_by_addr)} "
            f"ptr_symbols={len(ptr_name_by_addr)} sample={sample or 'none'} "
            f"objc_sample={objc_sample or 'none'}"
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

    original_slice = bytes(slice_blob)
    (
        dumped,
        write_min,
        write_max,
        emu_status,
        observed_runtime_strings,
        observed_runtime_candidates,
        observed_helper_literals,
    ) = _run_dynamic_emulation(
        slice_blob=slice_blob,
        arch=slice_info.arch,
        load_method=load_method,
        mprotect_stub=mprotect_stub,
        dyld_stub=dyld_stub,
        stub_name_by_addr=stub_name_by_addr,
        ptr_name_by_addr=ptr_name_by_addr,
        timeout_ms=effective_timeout_ms,
        max_insn=effective_max_insn,
        arm64_enable_early_stop=arm64_enable_early_stop,
    )
    if string_layer == "runnable":
        slice_blob[:] = dumped
    else:
        exec_ranges = _collect_exec_overlay_ranges(meta, len(slice_blob))
        changed = _overlay_dump_ranges(slice_blob, dumped, exec_ranges)
        _vlog(
            f"{slice_info.source}: {string_layer} overlay applied to executable ranges "
            f"count={len(exec_ranges)} bytes=0x{changed:x}"
        )
    load_commands_end = MACH_HEADER_64_SIZE + header.sizeofcmds
    if 0 < load_commands_end <= len(slice_blob):
        if slice_blob[:load_commands_end] != original_slice[:load_commands_end]:
            slice_blob[:load_commands_end] = original_slice[:load_commands_end]
            _vlog(
                f"{slice_info.source}: restored Mach-O header/load-commands region "
                f"(0x0-0x{load_commands_end:x}) after dynamic dump"
            )

    runtime_candidates: list[RuntimeStringCandidate] = []
    if string_layer == "none":
        observed_runtime_strings = []
    else:
        runtime_source = slice_blob if string_layer == "runnable" else memoryview(dumped)
        runtime_candidates = _extract_runtime_string_candidates(
            slice_blob=runtime_source,
            meta=meta,
            arch=slice_info.arch,
        )
        if (
            string_layer == "analysis"
            and not runtime_candidates
            and analysis_seed_blob is not None
            and len(analysis_seed_blob) == len(slice_blob)
        ):
            runtime_candidates = _extract_runtime_string_candidates(
                slice_blob=memoryview(analysis_seed_blob),
                meta=meta,
                arch=slice_info.arch,
            )
            if runtime_candidates:
                _vlog(
                    f"{slice_info.source}: runtime candidates sourced from static-prime "
                    f"snapshot count={len(runtime_candidates)}"
                )
        if observed_runtime_candidates:
            merged: dict[int, RuntimeStringCandidate] = {
                item.file_offset: item for item in runtime_candidates
            }
            for item in observed_runtime_candidates:
                prev = merged.get(item.file_offset)
                if prev is None or item.end_offset > prev.end_offset:
                    merged[item.file_offset] = item
            runtime_candidates = sorted(merged.values(), key=lambda item: item.file_offset)

        if observed_runtime_strings:
            decoded_set = {item.decoded for item in runtime_candidates}
            observed_runtime_strings = [
                text for text in observed_runtime_strings if text not in decoded_set
            ]

    runtime_found = len(runtime_candidates) + len(observed_runtime_strings)
    runtime_applied = 0
    runtime_key_patches = 0
    x86_slot_patches = 0
    x86_helper_patches = 0
    arm64_slot_patches = 0
    arm64_helper_patches = 0
    if runtime_candidates:
        _vlog(f"{slice_info.source}: runtime string candidates found={len(runtime_candidates)}")
        if VERBOSE:
            for item in runtime_candidates[:20]:
                _vlog(
                    f"{slice_info.source}: runtime string key=0x{item.key:02x} "
                    f"off=0x{item.file_offset:x} text={item.decoded!r}"
                )
    if observed_runtime_strings:
        _vlog(
            f"{slice_info.source}: runtime observed strings (memory-write trace) "
            f"found={len(observed_runtime_strings)}"
        )
        if VERBOSE:
            for text in observed_runtime_strings[:20]:
                _vlog(f"{slice_info.source}: runtime observed text={text!r}")

    if string_layer == "runnable":
        runtime_applied = _apply_runtime_string_candidates(slice_blob, runtime_candidates)
        if slice_info.arch == "x86_64":
            runtime_key_patches = _patch_runtime_xor_keys_x86(slice_blob, runtime_candidates)
            x86_slot_patches, x86_helper_patches = _apply_x86_runtime_helper_runnable_layer(
                slice_blob=slice_blob,
                meta=meta,
                helper_literals=observed_helper_literals,
                runtime_candidates=runtime_candidates,
            )
            runtime_applied += x86_slot_patches
            runtime_key_patches += x86_helper_patches
        elif slice_info.arch == "arm64":
            runtime_key_patches = _patch_runtime_xor_keys_arm64(slice_blob, runtime_candidates)
            arm64_slot_patches, arm64_helper_patches = _apply_arm64_runtime_helper_runnable_layer(
                slice_blob=slice_blob,
                meta=meta,
                helper_literals=observed_helper_literals,
                runtime_candidates=runtime_candidates,
            )
            runtime_applied += arm64_slot_patches
            runtime_key_patches += arm64_helper_patches
        elif runtime_found:
            _vlog(
                f"{slice_info.source}: runnable string layer currently has no code-key patching for "
                f"{slice_info.arch}; only data-side decoding applied"
            )
        if arm64_slot_patches or arm64_helper_patches:
            _vlog(
                f"{slice_info.source}: arm64 runnable helper patches "
                f"slots={arm64_slot_patches} helpers={arm64_helper_patches}"
            )
        if slice_info.arch == "x86_64" and observed_helper_literals:
            _vlog(
                f"{slice_info.source}: x86 runnable helper patches "
                f"slots={x86_slot_patches} helpers={x86_helper_patches}"
            )
        if runtime_applied or runtime_key_patches:
            _vlog(
                f"{slice_info.source}: runnable string layer applied={runtime_applied} "
                f"key_patches={runtime_key_patches}"
            )

    return DynamicSliceResult(
        arch=slice_info.arch,
        source=slice_info.source,
        slice_offset=slice_info.offset,
        slice_size=slice_info.size,
        load_method=load_method,
        mprotect_stub=mprotect_stub,
        mprotect_stub_symbol=stub_name_by_addr.get(mprotect_stub) if mprotect_stub is not None else None,
        dyld_get_slide_stub=dyld_stub,
        dyld_get_slide_stub_symbol=stub_name_by_addr.get(dyld_stub) if dyld_stub is not None else None,
        fixed_symbol_strings=fixed_symbol_strings,
        fixed_section_names=fixed_section_names,
        write_min=write_min,
        write_max=write_max,
        emu_status=emu_status,
        runtime_string_layer=string_layer,
        runtime_strings_found=runtime_found,
        runtime_strings_applied=runtime_applied,
        runtime_key_patches=runtime_key_patches,
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
    suppressed_rejects = 0
    reject_cap_notice_emitted = False
    scan_slots_total = max((scan_end - table_start) // 4, 1)
    progress_next_log_at = time.monotonic() + 1.5
    progress_last_slots = 0
    for table_off in range(table_start, scan_end - 3, 4):
        scanned_slots = ((table_off - table_start) // 4) + 1
        if VERBOSE:
            now = time.monotonic()
            if now >= progress_next_log_at and (scanned_slots - progress_last_slots) >= 8192:
                progress_pct = min(100.0, (scanned_slots * 100.0) / scan_slots_total)
                _vlog(
                    f"{slice_info.source}: scanning table candidates... "
                    f"offset=0x{table_off:x} progress={progress_pct:.1f}% "
                    f"candidates={candidate_count}"
                )
                progress_last_slots = scanned_slots
                progress_next_log_at = now + 1.5

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
            if VERBOSE and suppressed_rejects:
                _vlog(
                    f"{slice_info.source}: suppressed_rejects={suppressed_rejects} "
                    f"(showing first 12 only)"
                )
            return candidate, chunks
        except DeobfuscationError as exc:
            last_error = str(exc)
            if VERBOSE:
                if logged_rejects < 12:
                    _vlog(f"{slice_info.source}: reject table@0x{table_off:x}: {exc}")
                    logged_rejects += 1
                else:
                    suppressed_rejects += 1
                    if not reject_cap_notice_emitted:
                        _vlog(
                            f"{slice_info.source}: reject logs capped at 12; "
                            "continuing candidate scan..."
                        )
                        reject_cap_notice_emitted = True
            continue

    if not seen_nonzero:
        raise DeobfuscationError("no obfuscation metadata table found")
    if VERBOSE and suppressed_rejects:
        _vlog(
            f"{slice_info.source}: suppressed_rejects={suppressed_rejects} "
            f"(showing first 12 only)"
        )
    if last_error:
        raise DeobfuscationError(f"failed to locate valid obfuscation table: {last_error}")
    raise DeobfuscationError("failed to locate valid obfuscation table")


def _apply_static_string_pass(
    slice_blob: memoryview,
    meta: ParsedSliceMeta,
    arch: str,
    source: str,
) -> tuple[int, int, int]:
    if arch != "arm64":
        return 0, 0, 0

    candidates = _extract_runtime_string_candidates_arm64(slice_blob, meta)
    if not candidates:
        return 0, 0, 0

    applied = _apply_runtime_string_candidates(slice_blob, candidates)
    key_patches = _patch_runtime_xor_keys_arm64(slice_blob, candidates)
    _vlog(
        f"{source}: static string pass arm64 found={len(candidates)} "
        f"applied={applied} key_patches={key_patches}"
    )
    return len(candidates), applied, key_patches


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
        static_strings_found, static_strings_applied, static_key_patches = _apply_static_string_pass(
            slice_blob=slice_blob,
            meta=meta,
            arch=slice_info.arch,
            source=slice_info.source,
        )
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
        static_strings_found=static_strings_found,
        static_strings_applied=static_strings_applied,
        static_key_patches=static_key_patches,
    )


def _format_result(result: SliceResult) -> str:
    return (
        f"[{result.source}] arch={result.arch} "
        f"slice_off=0x{result.slice_offset:x} key=0x{result.xor_key:02x} "
        f"chunks={result.pair_count} patched=0x{result.patched_bytes:x} "
        f"table_off=0x{result.table_offset:x} "
        f"symfix={result.fixed_symbol_strings} secfix={result.fixed_section_names} "
        f"str_found={result.static_strings_found} "
        f"str_applied={result.static_strings_applied} "
        f"str_keypatch={result.static_key_patches}"
    )


def _format_dynamic_result(result: DynamicSliceResult) -> str:
    if result.write_min is None or result.write_max is None:
        write_info = "writes=none"
    else:
        write_info = f"writes=0x{result.write_min:x}-0x{result.write_max:x}"
    if result.mprotect_stub is None:
        mprotect_info = "none"
    else:
        mprotect_info = f"0x{result.mprotect_stub:x}"
        if result.mprotect_stub_symbol:
            mprotect_info += f"({result.mprotect_stub_symbol})"
    if result.dyld_get_slide_stub is None:
        dyld_info = "none"
    else:
        dyld_info = f"0x{result.dyld_get_slide_stub:x}"
        if result.dyld_get_slide_stub_symbol:
            dyld_info += f"({result.dyld_get_slide_stub_symbol})"
    return (
        f"[{result.source}] arch={result.arch} mode=dynamic "
        f"slice_off=0x{result.slice_offset:x} entry=0x{result.load_method:x} "
        f"mprotect_stub={mprotect_info} "
        f"dyld_stub={dyld_info} "
        f"symfix={result.fixed_symbol_strings} secfix={result.fixed_section_names} "
        f"runtime_layer={result.runtime_string_layer} "
        f"runtime_found={result.runtime_strings_found} "
        f"runtime_applied={result.runtime_strings_applied} "
        f"runtime_keypatch={result.runtime_key_patches} "
        f"{write_info} emu={result.emu_status}"
    )


def _print_next_step_guidance(out_path: Path) -> None:
    print("[NEXT] open the output file in IDA for second-stage processing.")
    print("[NEXT] run plugin `TNT Deobfuscator` with action `repair` on the loaded file.")
    print(f"[NEXT] target file: {out_path}")


def _looks_filename_stage1_processed(path: Path) -> bool:
    name = path.name.lower()
    return any(tag in name for tag in REPROCESS_NAME_HINTS)


def _collect_reprocess_hints(
    in_path: Path,
    _raw: bytearray,
    _target_slices: list[SliceInfo],
) -> list[str]:
    hints: list[str] = []
    if _looks_filename_stage1_processed(in_path):
        hints.append("filename looks processed")
    return hints


def _add_common_file_args(parser: argparse.ArgumentParser) -> None:
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
        "--verbose",
        action="store_true",
        help="enable verbose diagnostic logs (stderr)",
    )
    parser.add_argument(
        "--force-reprocess",
        action="store_true",
        help="force first-stage processing even if input appears already processed",
    )


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(argv) if argv is not None else list(sys.argv[1:])

    parser = argparse.ArgumentParser(
        description=(
            "TNT deobfuscator for Mach-O x86_64/arm64 binaries "
            "(default command is `static` when omitted)"
        )
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="install integrations (currently installs IDA plugin)",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="uninstall integrations (currently uninstalls IDA plugin)",
    )
    parser.add_argument(
        "--install-ida-plugin",
        action="store_true",
        help="install IDA plugin only",
    )
    parser.add_argument(
        "--uninstall-ida-plugin",
        action="store_true",
        help="uninstall IDA plugin only",
    )

    subparsers = parser.add_subparsers(dest="command")

    static_parser = subparsers.add_parser(
        "static",
        help="run static stage-1 deobfuscation",
    )
    _add_common_file_args(static_parser)
    static_parser.set_defaults(
        mode="static",
        emu_timeout_ms=None,
        emu_max_insn=None,
        dynamic_string_layer="none",
    )

    dynamic_parser = subparsers.add_parser(
        "dynamic",
        help="run dynamic stage-1 deobfuscation",
    )
    _add_common_file_args(dynamic_parser)
    dynamic_parser.add_argument(
        "--emu-timeout-ms",
        type=int,
        default=None,
        help=(
            "dynamic mode emulation timeout in milliseconds "
            f"(default: {DEFAULT_DYNAMIC_TIMEOUT_MS}; 0 = unlimited)"
        ),
    )
    dynamic_parser.add_argument(
        "--emu-max-insn",
        type=int,
        default=None,
        help=(
            "dynamic mode instruction count limit "
            f"(default: {DEFAULT_DYNAMIC_MAX_INSN}; 0 = unlimited)"
        ),
    )
    dynamic_parser.add_argument(
        "--dynamic-string-layer",
        choices=["none", "analysis", "runnable"],
        default="analysis",
        help=(
            "dynamic mode string handling: "
            "none=disable, analysis=extract/report runtime-decoded strings, "
            "runnable=apply string decode and patch matching decode keys"
        ),
    )
    dynamic_parser.add_argument(
        "--arm64-disable-early-stop",
        action="store_true",
        help=(
            "disable arm64 dynamic early-stop heuristic and run until timeout/max-insn "
            "(useful for collecting a fuller runtime string/code mutation set)"
        ),
    )
    dynamic_parser.set_defaults(mode="dynamic")

    parse_argv = raw_argv
    if raw_argv:
        first = raw_argv[0].strip().lower()
        if first not in {"static", "dynamic"} and first not in {
            "-h",
            "--help",
            "--install",
            "--uninstall",
            "--install-ida-plugin",
            "--uninstall-ida-plugin",
        }:
            parse_argv = ["static", *raw_argv]

    args = parser.parse_args(parse_argv)
    global VERBOSE
    VERBOSE = bool(getattr(args, "verbose", False))

    install_requested = bool(args.install or args.install_ida_plugin)
    uninstall_requested = bool(args.uninstall or args.uninstall_ida_plugin)

    if install_requested and uninstall_requested:
        parser.error(
            "cannot combine install and uninstall options in the same invocation"
        )

    if install_requested or uninstall_requested:
        if args.command is not None:
            parser.error("cannot combine static/dynamic command with install/uninstall options")
        if install_requested:
            installed = install_ida_plugin()
            if installed:
                print("[OK] install completed (IDA plugin).")
            else:
                print("[OK] install completed (nothing changed).")
            return 0
        removed = uninstall_ida_plugin()
        if removed:
            print("[OK] uninstall completed (IDA plugin).")
        else:
            print("[OK] uninstall completed (nothing to remove).")
        return 0

    if args.command is None:
        parser.error("missing command: use 'static' or 'dynamic'")

    in_path: Path = args.input
    out_path: Path = args.output if args.output else Path(f"{in_path}.deobf")
    try:
        same_file = in_path.resolve() == out_path.resolve()
    except Exception:
        same_file = str(in_path) == str(out_path)
    if same_file:
        print(
            "[ERROR] output path must differ from input path (non-destructive policy).",
            file=sys.stderr,
        )
        return 1

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
        f"timeout_ms={dynamic_timeout_ms} max_insn={dynamic_max_insn} "
        f"dynamic_string_layer={args.dynamic_string_layer}"
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

        if not args.force_reprocess:
            hints = _collect_reprocess_hints(in_path, raw, target_slices)
            if hints:
                print(
                    "[WARN] input appears already first-stage processed; "
                    "running first-stage again may flip patched regions.",
                    file=sys.stderr,
                )
                print(f"[WARN] hints: {', '.join(hints)}", file=sys.stderr)
                print(
                    "[NEXT] load this file in IDA and run plugin action `repair` for second-stage processing.",
                    file=sys.stderr,
                )
                print("[HINT] use --force-reprocess to continue anyway.", file=sys.stderr)
                return 2

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
                    prime_snapshot: bytes | None = None
                    prime_inplace = args.dynamic_string_layer == "runnable"
                    if prime_inplace:
                        prime_view = view
                    else:
                        prime_buf = bytearray(view)
                        prime_view = memoryview(prime_buf)
                    try:
                        prime_result = _patch_slice(prime_view, slice_info)
                        prime_key = prime_result.xor_key
                        if prime_inplace:
                            _vlog(
                                f"{slice_info.source}: dynamic prime succeeded "
                                f"key=0x{prime_result.xor_key:02x} patched=0x{prime_result.patched_bytes:x}"
                            )
                        else:
                            prime_snapshot = bytes(prime_view)
                            _vlog(
                                f"{slice_info.source}: dynamic prime (dry-run) "
                                f"key=0x{prime_result.xor_key:02x} patched=0x{prime_result.patched_bytes:x} "
                                f"(slice preserved for {args.dynamic_string_layer})"
                            )
                            if (
                                slice_info.arch == "x86_64"
                                and len(prime_snapshot) == len(view)
                            ):
                                header_for_seed = _parse_macho_header_64(view)
                                meta_for_seed = _parse_slice_meta(view, header_for_seed)
                                exec_ranges = _collect_exec_overlay_ranges(
                                    meta_for_seed, len(view)
                                )
                                seeded = _overlay_dump_ranges(
                                    view, prime_snapshot, exec_ranges
                                )
                                _vlog(
                                    f"{slice_info.source}: dynamic prime seeded executable ranges "
                                    f"count={len(exec_ranges)} bytes=0x{seeded:x} "
                                    f"(non-exec ranges preserved)"
                                )
                    except DeobfuscationError as exc:
                        _vlog(f"{slice_info.source}: dynamic prime skipped: {exc}")

                    dynamic_results.append(
                        _patch_slice_dynamic(
                            view,
                            slice_info,
                            timeout_ms=dynamic_timeout_ms,
                            max_insn=dynamic_max_insn,
                            string_layer=args.dynamic_string_layer,
                            xor_key_hint=prime_key,
                            arm64_enable_early_stop=not args.arm64_disable_early_stop,
                            analysis_seed_blob=prime_snapshot,
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
    _print_next_step_guidance(out_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

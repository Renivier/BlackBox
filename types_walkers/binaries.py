"""Structure walkers for executables, bytecode, databases and capture files."""

import struct
import zlib
from typing import Literal, TypeAlias

from .common import bad, context, cut, need, rolling, stop_or_bad, u16, u32

WalkStatus: TypeAlias = Literal["structure", "length", "header"]
WalkResult: TypeAlias = tuple[int | None, WalkStatus]


def read_leb(c: context, pos: int) -> tuple[int, int]:
    value: int = 0
    shift: int = 0

    for _ in range(5):
        need(c, pos, 1, "leb128 value")
        byte: int = c.mm[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7

        if not byte & 0x80:
            return value, pos

    raise bad("overlong leb128 value")


def walk_wasm(c: context) -> WalkResult:
    need(c, c.base, 8, "header")

    if c.mm[c.base + 4 : c.base + 8] != b"\x01\x00\x00\x00":
        raise bad("unsupported wasm version")

    pos: int = c.base + 8

    while pos < c.size:
        section_id: int = c.mm[pos]

        if section_id > 13:
            return stop_or_bad(
                c, pos, f"unknown section id {section_id} at offset {pos - c.base}"
            ), "structure"

        length: int
        length, pos = read_leb(c, pos + 1)
        pos += length
        need(c, pos, 0, "section")

    return pos, "structure"


def walk_pcap(c: context) -> WalkResult:
    mm = c.mm
    need(c, c.base, 24, "global header")

    byte_order: str = {b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}.get(
        mm[c.base : c.base + 4], "<"
    )
    snaplen: int = u32(c, c.base + 16, byte_order)
    pos: int = c.base + 24

    while pos < c.size:
        need(c, pos, 16, "record header")
        incl, orig = struct.unpack_from(byte_order + "II", mm, pos + 8)

        if incl > orig or (snaplen and incl > snaplen) or incl > 0x7FFFFFFF:
            return stop_or_bad(
                c, pos, f"implausible record length at offset {pos - c.base}"
            ), "structure"

        pos += 16 + incl
        need(c, pos, 0, "record")

    return pos, "structure"


def walk_pcapng(c: context) -> WalkResult:
    need(c, c.base, 12, "section header")

    order: str = "<" if u32(c, c.base + 8) == 0x1A2B3C4D else ">"
    pos: int = c.base

    while pos < c.size:
        need(c, pos, 12, "block header")
        length: int = u32(c, pos + 4, order)

        if length < 12 or length % 4:
            return stop_or_bad(
                c, pos, f"invalid block length at offset {pos - c.base}"
            ), "structure"

        need(c, pos, length, "block")

        if u32(c, pos + length - 4, order) != length:
            raise bad(f"block length trailer mismatch at offset {pos - c.base}")

        pos += length

    return pos, "structure"


def walk_elf(c: context) -> WalkResult:
    mm = c.mm
    need(c, c.base, 52, "elf header")

    wide: bool = mm[c.base + 4] == 2
    order: str = "<" if mm[c.base + 5] == 1 else ">"

    if mm[c.base + 4] not in (1, 2) or mm[c.base + 5] not in (1, 2):
        raise bad("invalid elf class or byte order")

    if wide:
        need(c, c.base, 64, "elf header")
        phoff, shoff = struct.unpack_from(order + "QQ", mm, c.base + 32)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(order + "HHHH", mm, c.base + 54)
        maxend: int = 64

    else:
        phoff, shoff = struct.unpack_from(order + "II", mm, c.base + 28)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(order + "HHHH", mm, c.base + 42)
        maxend = 52

    # Standard entry sizes can be unpacked in one pass; odd sizes fall back to a loop.

    if wide:
        ph_fmt: str = order + "8xQ16xQ16x"
        ph_size: int = 56
        sh_fmt: str = order + "4xI8x8xQQ24x"
        sh_size: int = 64

    else:
        ph_fmt = order + "4xI8xI12x"
        ph_size = 32
        sh_fmt = order + "4xI8xII16x"
        sh_size = 40

    if phnum:
        maxend = max(maxend, phoff + phnum * phentsize)
        need(c, c.base + phoff, phnum * phentsize, "program header table")

        if phentsize == ph_size:
            table: bytes = mm[c.base + phoff : c.base + phoff + phnum * phentsize]

            for offset, filesz in struct.iter_unpack(ph_fmt, table):
                maxend = max(maxend, offset + filesz)

        else:
            for i in range(phnum):
                at: int = c.base + phoff + i * phentsize

                if wide:
                    offset, filesz = (
                        struct.unpack_from(order + "Q", mm, at + 8)[0],
                        struct.unpack_from(order + "Q", mm, at + 32)[0],
                    )

                else:
                    offset, filesz = (
                        struct.unpack_from(order + "I", mm, at + 4)[0],
                        struct.unpack_from(order + "I", mm, at + 16)[0],
                    )

                maxend = max(maxend, offset + filesz)

    if shnum and shoff:
        maxend = max(maxend, shoff + shnum * shentsize)
        need(c, c.base + shoff, shnum * shentsize, "section header table")

        if shentsize == sh_size:
            table = mm[c.base + shoff : c.base + shoff + shnum * shentsize]

            for kind, offset, length in struct.iter_unpack(sh_fmt, table):
                if kind not in (0, 8):
                    maxend = max(maxend, offset + length)

        else:
            for i in range(shnum):
                at = c.base + shoff + i * shentsize

                if u32(c, at + 4, order) in (0, 8):
                    continue

                if wide:
                    offset, length = struct.unpack_from(order + "QQ", mm, at + 24)

                else:
                    offset, length = struct.unpack_from(order + "II", mm, at + 16)

                maxend = max(maxend, offset + length)

    need(c, c.base + maxend, 0, "segments or sections")
    return c.base + maxend, "structure"


def walk_pe(c: context) -> WalkResult:
    mm = c.mm
    need(c, c.base, 64, "dos header")

    lfanew: int = u32(c, c.base + 0x3C)
    pe: int = c.base + lfanew

    if lfanew >= 64 and pe + 4 > c.size:
        raise cut("pe header lies beyond the end of the file")

    if lfanew < 64 or mm[pe : pe + 4] != b"PE\x00\x00":
        last, pages = struct.unpack_from("<HH", mm, c.base + 2)

        if pages == 0:
            raise bad("dos header declares no pages")

        end: int = (pages - 1) * 512 + (last or 512)

        if end > c.size - c.base:
            raise cut(f"dos header declares {end} bytes but only {c.size - c.base} exist")

        return c.base + end, "length"

    need(c, pe, 24, "coff header")
    nsec, symptr, nsyms, optsize = struct.unpack_from("<2xH4xIIH", mm, pe + 4)

    opt: int = pe + 24
    need(c, opt, optsize, "optional header")
    magic: int = u16(c, opt)

    if magic not in (0x10B, 0x20B):
        raise bad("invalid optional header magic")

    dirs: int = opt + (112 if magic == 0x20B else 96)
    table: int = opt + optsize

    need(c, table, nsec * 40, "section table")

    end: int = table + nsec * 40 - c.base

    for i in range(nsec):
        raw_size, raw_ptr = struct.unpack_from("<II", mm, table + i * 40 + 16)

        if raw_ptr:
            end = max(end, raw_ptr + raw_size)

    if dirs + 40 <= opt + optsize and u32(c, dirs - 4) > 4:
        cert_off, cert_size = struct.unpack_from("<II", mm, dirs + 32)

        if cert_off and cert_size:
            end = max(end, cert_off + cert_size)

    if symptr:
        symbols_end: int = symptr + nsyms * 18
        need(c, c.base + symbols_end, 4, "coff string table")
        end = max(end, symbols_end + u32(c, c.base + symbols_end))

    need(c, c.base + end, 0, "sections")
    return c.base + end, "structure"


def walk_class(c: context) -> WalkResult:
    mm = c.mm
    need(c, c.base, 10, "class header")

    major, count = struct.unpack_from(">2xHH", mm, c.base + 4)

    if major < 45:
        raise bad("not a class file (version number too small)")

    pos: int = c.base + 10
    i: int = 1

    while i < count:
        need(c, pos, 1, "constant pool")
        tag: int = mm[pos]

        if tag == 1:
            need(c, pos, 3, "constant pool")
            pos += 3 + u16(c, pos + 1, ">")

        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            pos += 5

        elif tag in (5, 6):
            pos += 9
            i += 1

        elif tag in (7, 8, 16, 19, 20):
            pos += 3

        elif tag == 15:
            pos += 4

        else:
            raise bad(f"unknown constant pool tag {tag}")

        i += 1

    need(c, pos, 8, "class body")
    pos += 8 + 2 * u16(c, pos + 6, ">")

    def attributes(at: int, how_many: int) -> int:
        for _ in range(how_many):
            need(c, at, 6, "attribute")
            at += 6 + u32(c, at + 2, ">")
            need(c, at, 0, "attribute")

        return at

    for _ in range(2):  # fields, then methods
        need(c, pos, 2, "member table")
        members: int = u16(c, pos, ">")
        pos += 2

        for _ in range(members):
            need(c, pos, 8, "member")
            attr_count: int = u16(c, pos + 6, ">")
            pos = attributes(pos + 8, attr_count)

    need(c, pos, 2, "class attributes")
    pos = attributes(pos + 2, u16(c, pos, ">"))

    return pos, "structure"


def walk_sqlite(c: context) -> WalkResult:
    need(c, c.base, 100, "database header")

    raw: int = u16(c, c.base + 16, ">")
    page: int = 65536 if raw == 1 else raw

    if page < 512 or page & (page - 1):
        raise bad("invalid page size")

    pages: int = u32(c, c.base + 28, ">")
    valid: int | bool = pages and u32(c, c.base + 24, ">") == u32(c, c.base + 92, ">")
    have: int = c.size - c.base

    if valid:
        expected: int = pages * page

        if have < expected:
            raise cut(f"header lists {pages} pages but only {have // page} whole pages exist")

        return c.base + expected, "length"

    if have % page:
        raise cut("file ends in the middle of a page")

    return None, "header"


def walk_dex(c: context) -> WalkResult:
    need(c, c.base, 112, "header")

    declared: int = u32(c, c.base + 32)

    if u32(c, c.base + 36) != 0x70 or u32(c, c.base + 40) != 0x12345678:
        raise bad("invalid header size or endian tag")

    if declared > c.size - c.base:
        raise cut(f"header declares {declared} bytes but only {c.size - c.base} exist")

    end: int = c.base + declared

    if c.deep and rolling(c, zlib.adler32, c.base + 12, end, 1) != u32(c, c.base + 8):
        raise bad("adler32 checksum mismatch", end)

    return end, "length"

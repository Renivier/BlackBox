"""Structure walkers for archive and compression formats."""

import bz2
import lzma
import mmap
import struct
import zipfile
import zlib
from collections.abc import Callable
from functools import partial
from typing import Literal, Protocol, TypeAlias

from .common import bad, context, cut, need, step, u16, u32

WalkDepth: TypeAlias = Literal["header", "structure", "ends", "length"]
WalkResult: TypeAlias = tuple[int | None, WalkDepth]
DecompressErrors: TypeAlias = tuple[type[Exception], ...]


class StreamDecompressor(Protocol):
    """Common interface implemented by the bz2 and lzma decompressors."""

    eof: bool
    needs_input: bool
    unused_data: bytes

    def decompress(self, data: bytes, max_length: int = -1) -> bytes: ...


class ZlibDecompressor(Protocol):
    """The subset of zlib.Decompress used by drain_zlib."""

    eof: bool
    unconsumed_tail: bytes
    unused_data: bytes

    def decompress(self, data: bytes, max_length: int = 0) -> bytes: ...


def walk_zip(c: context) -> WalkResult:
    mm: mmap.mmap = c.mm
    low: int = max(c.base, c.size - 65557)
    eocd: int = c.size
    found: int | None = None
    while True:
        eocd = mm.rfind(b"PK\x05\x06", low, eocd)
        if eocd == -1:
            break
        if eocd + 22 <= c.size and eocd + 22 + u16(c, eocd + 20) <= c.size:
            found = eocd
            break
    if found is None:
        raise cut("no end-of-central-directory record")
    eocd = found
    eocd_fields: tuple[int, int, int, int] = struct.unpack_from("<6xHIIH", mm, eocd + 4)
    entries, cd_size, cd_offset, comment = eocd_fields
    end: int = eocd + 22 + comment
    if 0xFFFFFFFF in (cd_size, cd_offset) or entries == 0xFFFF:
        return end, "header"  # zip64: not walked
    cd_start: int = eocd - cd_size
    if cd_start < c.base:
        raise bad("central directory is larger than the file", end)
    if cd_size and mm[cd_start : cd_start + 4] != b"PK\x01\x02":
        raise bad("central directory is not where the end record says", end)
    shift: int = cd_start - cd_offset  # bytes in front of the archive
    pos: int = cd_start
    limit: int = entries if c.deep else min(entries, 2)
    for i in range(limit):
        if mm[pos : pos + 4] != b"PK\x01\x02":
            raise bad(f"central directory entry {i} is damaged", end)
        entry_lengths: tuple[int, int, int] = struct.unpack_from("<HHH", mm, pos + 28)
        name_len, extra_len, note_len = entry_lengths
        local: int = u32(c, pos + 42)
        if local != 0xFFFFFFFF and mm[shift + local : shift + local + 4] != b"PK\x03\x04":
            raise bad(f"entry {i} points at a missing local header", end)
        pos += 46 + name_len + extra_len + note_len
    if c.deep:
        try:
            with zipfile.ZipFile(c.path) as archive:
                broken: str | None = archive.testzip()
        except (RuntimeError, NotImplementedError):
            broken = None  # encrypted or unsupported entries
        except (
            zipfile.BadZipFile,
            zlib.error,
            lzma.LZMAError,
            EOFError,
            OSError,
            ValueError,
        ) as error:
            raise bad(f"zip data error: {error}", end)
        if broken:
            raise bad(f"crc mismatch in entry {broken}", end)
        return end, "structure"
    return end, "ends"


def drain_zlib(c: context) -> WalkResult:
    pos: int = c.base
    while True:
        d: ZlibDecompressor = zlib.decompressobj(31)
        try:
            while not d.eof:
                if d.unconsumed_tail:
                    data: bytes = d.unconsumed_tail
                else:
                    if pos >= c.size:
                        raise cut("compressed data ends before the end-of-stream marker")
                    data: bytes = c.mm[pos : pos + step]
                    pos += len(data)
                d.decompress(data, 65536)
        except zlib.error as error:
            raise bad(f"gzip data error: {error}")
        pos -= len(d.unused_data)
        if c.mm[pos : pos + 3] != b"\x1f\x8b\x08":
            return pos, "structure"


def drain_stream(
    c: context,
    make: Callable[[], StreamDecompressor],
    magic: bytes,
    label: str,
    errors: DecompressErrors,
    pad_nulls: bool = False,
) -> WalkResult:
    pos: int = c.base
    while True:
        d: StreamDecompressor = make()
        try:
            while not d.eof:
                if d.needs_input:
                    if pos >= c.size:
                        raise cut(f"{label} data ends before the end-of-stream marker")
                    data: bytes = c.mm[pos : pos + step]
                    pos += len(data)
                else:
                    data = b""
                d.decompress(data, 65536)
        except errors as error:
            raise bad(f"{label} data error: {error}")
        pos -= len(d.unused_data)
        if pad_nulls:
            while c.mm[pos : pos + 4] == b"\x00\x00\x00\x00":
                pos += 4
        if c.mm[pos : pos + len(magic)] != magic:
            return pos, "structure"


def walk_gzip(c: context) -> WalkResult:
    need(c, c.base, 18, "gzip member")
    if c.mm[c.base + 2] != 8:
        raise bad("unknown compression method")
    if c.mm[c.base + 3] & 0xE0:
        raise bad("reserved flag bits are set in the gzip header")
    if c.deep:
        return drain_zlib(c)
    return None, "header"


def walk_bzip2(c: context) -> WalkResult:
    need(c, c.base, 10, "bzip2 header")
    if not 0x31 <= c.mm[c.base + 3] <= 0x39:
        raise bad("invalid block size digit")
    if c.mm[c.base + 4 : c.base + 10] not in (
        b"\x31\x41\x59\x26\x53\x59",
        b"\x17\x72\x45\x38\x50\x90",
    ):
        raise bad("first block does not start with the bzip2 block magic")
    if c.deep:
        return drain_stream(c, bz2.BZ2Decompressor, b"BZh", "bzip2", (OSError, ValueError))
    return None, "header"


def walk_xz(c: context) -> WalkResult:
    mm: mmap.mmap = c.mm
    need(c, c.base, 24, "xz stream")
    if zlib.crc32(mm[c.base + 6 : c.base + 8]) != u32(c, c.base + 8):
        raise bad("stream header checksum mismatch")
    if c.deep:
        make = partial(lzma.LZMADecompressor, format=lzma.FORMAT_XZ)
        return drain_stream(c, make, b"\xfd7zXZ\x00", "xz", (lzma.LZMAError,), pad_nulls=True)
    flags: bytes = mm[c.base + 6 : c.base + 8]
    stop: int = c.size
    low: int = max(c.base + 12, c.size - 4096)
    while True:
        at: int = mm.rfind(b"YZ", low, stop)
        if at == -1:
            raise cut("no valid xz footer near the end of the file")
        end: int = at + 2
        if (
            end - 12 >= c.base + 12
            and mm[end - 4 : end - 2] == flags
            and zlib.crc32(mm[end - 8 : end - 2]) == u32(c, end - 12)
        ):
            return end, "ends"
        stop = at + 1


def walk_zstd(c: context) -> WalkResult:
    mm: mmap.mmap = c.mm
    pos: int = c.base
    while True:
        need(c, pos, 5, "frame header")
        magic: int = u32(c, pos)
        if 0x184D2A50 <= magic <= 0x184D2A5F:
            need(c, pos, 8, "skippable frame")
            pos += 8 + u32(c, pos + 4)
            need(c, pos, 0, "skippable frame")
        elif magic == 0xFD2FB528:
            desc: int = mm[pos + 4]
            if desc & 0x08:
                raise bad("reserved bit set in the frame descriptor")
            descriptor_flags: tuple[int, int, int, int] = (
                (desc >> 5) & 1,
                (desc >> 2) & 1,
                desc & 3,
                desc >> 6,
            )
            single, checksum, dict_flag, fcs_flag = descriptor_flags
            fcs: int = (1 if single else 0) if fcs_flag == 0 else (2, 4, 8)[fcs_flag - 1]
            pos += 5 + (0 if single else 1) + (0, 1, 2, 4)[dict_flag] + fcs
            while True:
                need(c, pos, 3, "block header")
                head: int = mm[pos] | (mm[pos + 1] << 8) | (mm[pos + 2] << 16)
                block_header: tuple[int, int] = ((head >> 1) & 3, head >> 3)
                kind, length = block_header
                if kind == 3:
                    raise bad("reserved block type")
                pos += 3 + (1 if kind == 1 else length)
                need(c, pos, 0, "block")
                if head & 1:
                    break
            if checksum:
                pos += 4
                need(c, pos, 0, "content checksum")
        else:
            return pos, "structure"  # not a frame: trailing data
        if pos >= c.size:
            return pos, "structure"


def walk_lz4(c: context) -> WalkResult:
    mm: mmap.mmap = c.mm
    pos: int = c.base
    while True:
        need(c, pos, 7, "frame header")
        flg: int = mm[pos + 4]
        if flg >> 6 != 1:
            raise bad("unsupported lz4 frame version")
        pos += 7 + (8 if flg & 0x08 else 0) + (4 if flg & 0x01 else 0)
        while True:
            need(c, pos, 4, "block header")
            block: int = u32(c, pos)
            pos += 4
            if block == 0:
                break
            pos += (block & 0x7FFFFFFF) + (4 if flg & 0x10 else 0)
            need(c, pos, 0, "block")
        if flg & 0x04:
            pos += 4
            need(c, pos, 0, "content checksum")
        if mm[pos : pos + 4] != b"\x04\x22\x4d\x18":
            return pos, "structure"


def tar_checksum_ok(block: bytes) -> bool:
    try:
        stored: int = int(block[148:156].strip(b"\x00 ") or b"0", 8)
    except ValueError:
        return False
    raw: bytes = block[:148] + b" " * 8 + block[156:]
    return stored == sum(raw) or stored == sum(b - 256 if b > 127 else b for b in raw)


def walk_tar(c: context) -> WalkResult:
    mm: mmap.mmap = c.mm
    pos: int = c.base
    while True:
        if pos + 512 > c.size:
            raise cut(
                "archive ends without an end-of-archive marker"
                if pos == c.size
                else "partial header block at the end of the file"
            )
        block: bytes = mm[pos : pos + 512]
        if block.count(0) == 512:
            pos += 512
            if pos + 512 <= c.size and mm[pos : pos + 512].count(0) == 512:
                pos += 512
            record_end: int = c.base + (((pos - c.base) + 10239) // 10240) * 10240
            stop: int = min(record_end, c.size)
            if not mm[pos:stop].strip(b"\x00"):
                pos = stop
            return pos, "structure"
        if not tar_checksum_ok(block):
            raise bad(f"header checksum mismatch at offset {pos - c.base}")
        field: bytes = block[124:136]
        try:
            length: int = (
                int.from_bytes(field[1:], "big")
                if field[0] & 0x80
                else int(field.strip(b"\x00 ") or b"0", 8)
            )
        except ValueError:
            raise bad(f"unreadable size field at offset {pos - c.base}")
        flag: bytes = block[156:157]
        if flag in (b"1", b"2", b"3", b"4", b"5", b"6"):
            length = 0
        pos += 512
        if flag == b"S":  # old gnu sparse: extension blocks follow
            more = block[482]
            while more:
                need(c, pos, 512, "sparse extension block")
                more = mm[pos + 504]
                pos += 512
        pos += ((length + 511) // 512) * 512
        if pos > c.size:
            raise cut("an entry's data runs past the end of the file")


def walk_7z(c: context) -> WalkResult:
    need(c, c.base, 32, "signature header")
    if zlib.crc32(c.mm[c.base + 12 : c.base + 32]) != u32(c, c.base + 8):
        raise bad("start header checksum mismatch")
    next_header: tuple[int, int, int] = struct.unpack_from("<QQI", c.mm, c.base + 12)
    offset, length, crc = next_header
    end = c.base + 32 + offset + length
    if end > c.size:
        raise cut(f"header expects {end - c.base} bytes but only {c.size - c.base} exist")
    if length and length <= 1 << 24 and zlib.crc32(c.mm[end - length : end]) != crc:
        raise bad("next header checksum mismatch", end)
    return end, "structure"


def walk_cab(c: context) -> WalkResult:
    need(c, c.base, 36, "header")
    if c.mm[c.base + 25] != 1 or c.mm[c.base + 24] != 3:
        raise bad("unsupported cabinet version")
    total: int = u32(c, c.base + 8)
    if total > c.size - c.base:
        raise cut(f"header declares {total} bytes but only {c.size - c.base} exist")
    return c.base + total, "length"


def walk_cpio(c: context) -> WalkResult:
    mm: mmap.mmap = c.mm
    pos: int = c.base
    newc: bool = mm[pos : pos + 6] in (b"070701", b"070702")
    while True:
        if pos >= c.size:
            raise cut("archive ends without a TRAILER!!! entry")
        head: int = 110 if newc else 76
        need(c, pos, head, "entry header")
        try:
            if newc:
                if mm[pos : pos + 5] != b"07070":
                    raise bad(f"bad entry magic at offset {pos - c.base}")
                fields: list[int] = [
                    int(mm[pos + 6 + 8 * i : pos + 14 + 8 * i], 16) for i in range(13)
                ]
                entry_sizes: tuple[int, int] = (fields[6], fields[11])
                filesize, namesize = entry_sizes
            else:
                if mm[pos : pos + 6] != b"070707":
                    raise bad(f"bad entry magic at offset {pos - c.base}")
                entry_sizes: tuple[int, int] = (
                    int(mm[pos + 59 : pos + 65], 8),
                    int(mm[pos + 65 : pos + 76], 8),
                )
                namesize, filesize = entry_sizes
        except ValueError:
            raise bad(f"unreadable entry header at offset {pos - c.base}")

        def align(value: int) -> int:
            return c.base + (((value - c.base) + 3) & ~3) if newc else value

        name_end: int = pos + head + namesize
        need(c, name_end, 0, "entry name")
        name: bytes = mm[pos + head : name_end].rstrip(b"\x00")
        data_end: int = align(name_end) + filesize
        need(c, data_end, 0, "entry data")
        pos = align(data_end)
        if name == b"TRAILER!!!":
            stop: int = min(c.base + (((pos - c.base) + 511) // 512) * 512, c.size)
            if not mm[pos:stop].strip(b"\x00"):
                pos = stop
            return pos, "structure"

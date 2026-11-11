"""Structure walkers for image formats."""

import re
import struct
import zlib
from typing import Literal, TypeAlias

from .common import bad, context, cut, need, rolling, u16, u32

WalkStatus: TypeAlias = Literal["structure", "header", "length"]
WalkResult: TypeAlias = tuple[int | None, WalkStatus]
Endian: TypeAlias = Literal["<", ">"]
TIFFArray: TypeAlias = tuple[int, ...]

marker_re: re.Pattern[bytes] = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")


def walk_png(c: context) -> WalkResult:
    mm = c.mm
    pos: int = c.base + 8
    first: bool = True
    crc_limit: int | None = None if c.deep else 1 << 20

    while True:
        need(c, pos, 12, "chunk")

        length, kind = struct.unpack_from(">I4s", mm, pos)

        if not kind.isalpha():
            raise bad(f"invalid chunk type at offset {pos - c.base}")

        if first:
            if kind != b"IHDR" or length != 13:
                raise bad("first chunk is not a valid IHDR")
            first = False

        if length > 0x7FFFFFFF:
            raise bad(f"{kind.decode()} chunk has an impossible length")

        chunk_end: int = pos + 12 + length
        need(c, chunk_end, 0, f"{kind.decode()} chunk")

        if crc_limit is None or length <= crc_limit:
            stored: int = u32(c, pos + 8 + length, ">")

            if rolling(c, zlib.crc32, pos + 4, pos + 8 + length, 0) != stored:
                raise bad(f"crc mismatch in {kind.decode()} chunk at offset {pos - c.base}")

        if kind == b"IEND":
            if length != 0:
                raise bad("IEND chunk is not empty")
            return chunk_end, "structure"

        pos = chunk_end


def walk_jpeg(c: context) -> WalkResult:
    mm = c.mm
    pos: int = c.base + 2

    while True:
        while pos + 1 < c.size and mm[pos] == 0xFF and mm[pos + 1] == 0xFF:
            pos += 1  # fill bytes

        need(c, pos, 2, "marker")

        if mm[pos] != 0xFF:
            raise bad(f"expected a marker at offset {pos - c.base}")

        marker: int = mm[pos + 1]

        if marker == 0xD9:
            return pos + 2, "structure"

        if marker == 0x00:
            raise bad(f"stray 0xff00 at offset {pos - c.base}")

        if marker == 0x01 or 0xD0 <= marker <= 0xD8:
            pos += 2
            continue

        need(c, pos, 4, "segment header")

        length: int = (mm[pos + 2] << 8) | mm[pos + 3]

        if length < 2:
            raise bad(f"segment length {length} at offset {pos - c.base}")

        seg_end: int = pos + 2 + length
        need(c, seg_end, 0, "segment")

        if marker == 0xDA:  # start of scan: entropy data follows
            found: re.Match[bytes] | None = marker_re.search(mm, seg_end)

            if found is None:
                raise cut("scan data runs to the end of the file without an EOI marker")

            pos = found.start()

        else:
            pos = seg_end


def skip_subblocks(c: context, pos: int) -> int:
    while True:
        need(c, pos, 1, "sub-block")

        n: int = c.mm[pos]
        pos += 1 + n

        if n == 0:
            return pos


def walk_gif(c: context) -> WalkResult:
    mm = c.mm

    need(c, c.base, 13, "header")

    packed: int = mm[c.base + 10]
    pos: int = c.base + 13

    if packed & 0x80:
        pos += 3 * (2 << (packed & 7))

    while True:
        need(c, pos, 1, "block")

        kind: int = mm[pos]

        if kind == 0x3B:
            return pos + 1, "structure"

        if kind == 0x2C:
            need(c, pos, 10, "image descriptor")

            local: int = mm[pos + 9]
            pos += 10

            if local & 0x80:
                pos += 3 * (2 << (local & 7))

            need(c, pos, 1, "image data")
            pos = skip_subblocks(c, pos + 1)

        elif kind == 0x21:
            need(c, pos, 2, "extension")
            pos = skip_subblocks(c, pos + 2)

        else:
            raise bad(f"unknown block 0x{kind:02x} at offset {pos - c.base}")


def walk_bmp(c: context) -> tuple[int | None, Literal["header", "length"]]:
    need(c, c.base, 18, "header")

    declared, data_off = struct.unpack_from("<I4xI", c.mm, c.base + 2)

    dib_size: int = u32(c, c.base + 14)

    if dib_size not in (12, 40, 52, 56, 64, 108, 124):
        raise bad("unknown DIB header size")

    if declared == 0:
        return None, "header"

    if declared > c.size - c.base:
        raise cut(f"header declares {declared} bytes but only {c.size - c.base} exist")

    if data_off > declared:
        raise bad("pixel data offset lies beyond the declared file size")

    return c.base + declared, "length"


def walk_ico(c: context) -> WalkResult:
    need(c, c.base, 6, "header")

    count: int = u16(c, c.base + 4)

    if count == 0:
        raise bad("icon directory is empty")

    table: int = c.base + 6

    need(c, table, 16 * count, "icon directory")

    end: int = table + 16 * count

    for i in range(count):
        nbytes, offset = struct.unpack_from("<II", c.mm, table + 16 * i + 8)

        if offset < 6 + 16 * count:
            raise bad(f"image {i} points into the directory")

        end = max(end, c.base + offset + nbytes)

    need(c, end, 0, "image data")

    return end, "structure"


tiff_sizes: dict[int, int] = {
    1: 1,
    2: 1,
    3: 2,
    4: 4,
    5: 8,
    6: 1,
    7: 1,
    8: 2,
    9: 4,
    10: 8,
    11: 4,
    12: 8,
    13: 4,
    16: 8,
    17: 8,
    18: 8,
}


def walk_tiff(c: context) -> WalkResult:
    mm = c.mm

    need(c, c.base, 8, "header")

    order: Endian = "<" if mm[c.base : c.base + 2] == b"II" else ">"

    if u16(c, c.base + 2, order) != 42:
        raise bad("bad tiff version number")

    queue: list[int] = [u32(c, c.base + 4, order)]
    seen: set[int] = set()
    maxend: int = c.base + 8

    while queue:
        ifd: int = queue.pop()

        if not ifd:
            continue

        if ifd in seen:
            raise bad("image directories form a loop")

        seen.add(ifd)

        if len(seen) > 4096:
            raise bad("too many image directories")

        pos: int = c.base + ifd

        need(c, pos, 2, "directory")

        n: int = u16(c, pos, order)

        need(c, pos, 2 + 12 * n + 4, "directory entries")

        maxend = max(maxend, pos + 2 + 12 * n + 4)

        arrays: dict[int, TIFFArray] = {}

        for k in range(n):
            tag, kind, count, value = struct.unpack_from(order + "HHII", mm, pos + 2 + 12 * k)

            each: int | None = tiff_sizes.get(kind)

            if each is None:
                continue

            total: int = each * count
            where: int = pos + 2 + 12 * k + 8  # inline value position

            if total > 4:
                where = c.base + value
                maxend = max(maxend, where + total)

            if tag in (34665, 34853):
                queue.append(value)

            elif tag in (273, 279, 324, 325) and kind in (3, 4) and count <= 1 << 20:
                need(c, where, total, "strip table")

                fmt: str = "H" if kind == 3 else "I"
                arrays[tag] = struct.unpack_from(order + str(count) + fmt, mm, where)

        for offsets, counts in ((273, 279), (324, 325)):
            if offsets in arrays and counts in arrays:
                for off, length in zip(arrays[offsets], arrays[counts]):
                    maxend = max(maxend, c.base + off + length)

        queue.append(u32(c, pos + 2 + 12 * n, order))

    need(c, maxend, 0, "image data")

    return None, "structure"

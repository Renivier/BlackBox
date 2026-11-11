"""Structure walkers for audio and video containers."""

import struct
from typing import Literal, TypeAlias

from .common import bad, context, cut, need, u32

WalkStatus: TypeAlias = Literal["structure", "header", "length"]
WalkResult: TypeAlias = tuple[int | None, WalkStatus]
Endian: TypeAlias = Literal["<", ">"]
OggStreams: TypeAlias = dict[int, bool]

known_boxes: set[bytes] = {
    b"ftyp",
    b"moov",
    b"mdat",
    b"free",
    b"skip",
    b"wide",
    b"uuid",
    b"moof",
    b"mfra",
    b"meta",
    b"styp",
    b"sidx",
    b"pdin",
    b"jP  ",
    b"jp2h",
    b"jp2c",
    b"jp2i",
    b"xml ",
    b"rreq",
    b"ssix",
    b"prft",
    b"emsg",
    b"pnot",
    b"PICT",
    b"junk",
    b"clip",
}


def walk_riff(c: context) -> tuple[int | None, Literal["header", "length"]]:
    mm = c.mm
    pos: int = c.base

    while True:
        need(c, pos, 12, "riff header")

        tag: bytes = mm[pos : pos + 4]

        if tag not in (b"RIFF", b"RIFX", b"RF64", b"BW64"):
            raise bad("missing RIFF tag")

        order: Endian = ">" if tag == b"RIFX" else "<"
        declared: int = u32(c, pos + 4, order)

        if tag in (b"RF64", b"BW64") and declared == 0xFFFFFFFF:
            if mm[pos + 12 : pos + 16] != b"ds64" or pos + 28 > c.size:
                return None, "header"

            declared = struct.unpack_from("<Q", mm, pos + 20)[0]  # real size lives in ds64

        elif declared in (0, 0xFFFFFFFF):
            return None, "header"  # streamed file, size unknown

        end: int = pos + 8 + declared + (declared & 1)

        if end == c.size + 1 and declared & 1:
            end = c.size  # writer left out the final pad byte

        if end > c.size:
            raise cut(f"header declares {end - pos} bytes but only {c.size - pos} exist")

        if mm[end : end + 4] == b"RIFF" and mm[end + 8 : end + 12] == b"AVIX":
            pos = end  # avi opendml continuation
            continue

        return end, "length"


def walk_aiff(c: context) -> tuple[int, Literal["length"]]:
    need(c, c.base, 12, "iff header")

    declared: int = u32(c, c.base + 4, ">")
    end: int = c.base + 8 + declared + (declared & 1)

    if end > c.size:
        raise cut(f"header declares {end - c.base} bytes but only {c.size - c.base} exist")

    return end, "length"


def walk_boxes(c: context, required: bytes | None = None) -> WalkResult:
    mm = c.mm
    pos: int = c.base
    seen: set[bytes] = set()

    while pos < c.size:
        if c.size - pos < 8 and not mm[pos : c.size].strip(b"\x00"):
            break  # quicktime zero terminator

        need(c, pos, 8, "box header")

        length, kind = struct.unpack_from(">I4s", mm, pos)

        header: int = 8
        printable: bool = all(32 <= b < 127 or b == 0xA9 for b in kind)

        if length == 1 and printable:
            need(c, pos, 16, "large box header")
            length, header = struct.unpack_from(">Q", mm, pos + 8)[0], 16

        elif length == 0 and printable:
            seen.add(kind)
            pos = c.size  # box extends to the end of the file
            break

        if not printable or length < header:
            if seen:
                break  # trailing data after the last box

            raise bad(f"invalid box at offset {pos - c.base}")

        if pos + length > c.size:
            if seen and kind not in known_boxes:
                break  # junk that merely looks like a box header

            raise cut(f"{kind.decode('latin-1')} box runs past the end of the file")

        seen.add(kind)
        pos += length

    if required and required not in seen and not (required == b"moov" and b"moof" in seen):
        raise cut(f"no {required.decode()} box")

    return pos, "structure"


def walk_ogg(c: context) -> WalkResult:
    mm = c.mm
    pos: int = c.base
    streams: OggStreams = {}

    while pos < c.size:
        if mm[pos : pos + 4] != b"OggS":
            if mm.find(b"OggS", pos) != -1:
                raise bad(f"lost page sync at offset {pos - c.base}")

            break

        need(c, pos, 27, "page header")

        htype: int = mm[pos + 5]
        serial: int = u32(c, pos + 14)
        nseg: int = mm[pos + 26]

        need(c, pos, 27 + nseg, "segment table")

        end: int = pos + 27 + nseg + sum(mm[pos + 27 : pos + 27 + nseg])

        need(c, end, 0, "page")

        if htype & 2:
            streams[serial] = False

        if htype & 4:
            streams[serial] = True

        pos = end

    if not streams:
        raise bad("no stream start page")

    if not all(streams.values()):
        raise cut("a logical stream has no end-of-stream page")

    return pos, "structure"


def walk_flac(c: context) -> tuple[None, Literal["header"]]:
    mm = c.mm
    pos: int = c.base + 4
    first: bool = True

    while True:
        need(c, pos, 4, "metadata block header")

        head: int = mm[pos]
        kind: int = head & 0x7F
        length: int = (mm[pos + 1] << 16) | (mm[pos + 2] << 8) | mm[pos + 3]

        if first and (kind != 0 or length != 34):
            raise bad("first metadata block is not STREAMINFO")

        first = False

        if kind == 127:
            raise bad("invalid metadata block type")

        pos += 4 + length

        need(c, pos, 0, "metadata block")

        if head & 0x80:
            break

    need(c, pos, 2, "first audio frame")

    if mm[pos] != 0xFF or mm[pos + 1] & 0xFE != 0xF8:
        raise bad("no frame sync after the metadata")

    return None, "header"


def walk_mp3(c: context) -> tuple[None, Literal["header"]]:
    mm = c.mm

    need(c, c.base, 10, "id3 header")

    if mm[c.base + 3] not in (2, 3, 4):
        raise bad("unknown id3 version")

    if any(b & 0x80 for b in mm[c.base + 6 : c.base + 10]):
        raise bad("id3 size field is not synchsafe")

    tag: int = 0

    for b in mm[c.base + 6 : c.base + 10]:
        tag = (tag << 7) | b

    footer_size: int = 10 if mm[c.base + 5] & 0x10 else 0
    pos: int = c.base + 10 + tag + footer_size

    need(c, pos, 0, "id3 tag")

    while pos < c.size and mm[pos] == 0:
        pos += 1

    need(c, pos, 4, "first audio frame")

    if mm[pos] != 0xFF or mm[pos + 1] & 0xE0 != 0xE0:
        raise bad("no mpeg frame sync after the id3 tag")

    return None, "header"

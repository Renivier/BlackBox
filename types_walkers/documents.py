"""Structure walkers for document formats."""

import re
import struct
from typing import Literal, TypeAlias
from xml.parsers import expat

from .common import allowed_prefix, bad, context, cut, need, step, u16, u32, ws

WalkStatus: TypeAlias = Literal["structure", "header"]
WalkResult: TypeAlias = tuple[int | None, WalkStatus]
XRefEntry: TypeAlias = tuple[int, int]
XMLAttributes: TypeAlias = dict[str, str]

num_re: re.Pattern[bytes] = re.compile(rb"\s*(\d+)\s*")
obj_head_re: re.Pattern[bytes] = re.compile(rb"\s*(\d+)\s+\d+\s+obj")
subsection_re: re.Pattern[bytes] = re.compile(rb"(\d+)\s+(\d+)")
entry_re: re.Pattern[bytes] = re.compile(rb"(\d{10})\s+(\d{5})\s+([nf])")


def check_xref_table(c: context, pos: int) -> tuple[int, int]:
    cap: int = (64 << 20) if c.deep else (1 << 20)
    lines: list[bytes] = c.mm[pos : pos + cap].splitlines()
    entries: list[XRefEntry] = []
    i: int = 1

    while i < len(lines):
        line: bytes = lines[i].strip()
        i += 1

        if not line:
            continue

        sub: re.Match[bytes] | None = subsection_re.fullmatch(line)

        if not sub:
            break

        first, count = int(sub[1]), int(sub[2])

        for k in range(count):
            while i < len(lines) and not lines[i].strip():
                i += 1

            if i >= len(lines):
                break

            entry: re.Match[bytes] | None = entry_re.match(lines[i].strip())
            i += 1

            if entry and entry[3] == b"n":
                entries.append((first + k, int(entry[1])))

    if not c.deep and len(entries) > 200:
        stride: float = len(entries) / 200
        entries = [entries[int(j * stride)] for j in range(200)]

    wrong: int = 0

    for number, offset in entries:
        p: int = c.base + offset
        head: re.Match[bytes] | None = obj_head_re.match(c.mm[p : p + 40]) if p < c.size else None

        if not head or int(head[1]) != number:
            wrong += 1

    return len(entries), wrong


linearized_re: re.Pattern[bytes] = re.compile(rb"/L\s+(\d+)")


def walk_pdf(c: context) -> WalkResult:
    mm = c.mm
    lin: int = mm.find(b"/Linearized", c.base, min(c.size, c.base + 1024))

    if lin != -1:  # linearized files state their own length
        declared: re.Match[bytes] | None = linearized_re.search(mm[lin : lin + 200])

        if declared and int(declared[1]) > c.size - c.base:
            raise cut(
                f"linearization header says {int(declared[1])} bytes, but only {c.size - c.base} exist"
            )

    eof: int = mm.rfind(b"%%EOF", max(c.base, c.size - 2048))

    if eof == -1:
        eof = mm.rfind(b"%%EOF", c.base)

    if eof == -1:
        raise cut("no %%EOF marker anywhere in the file")

    end: int = eof + 5
    sx: int = mm.rfind(b"startxref", max(c.base, eof - 128), eof)

    if sx == -1:
        raise bad("no startxref right before %%EOF", end)

    num: re.Match[bytes] | None = num_re.fullmatch(mm[sx + 9 : eof])

    if not num:
        raise bad("startxref is not followed by a valid offset", end)

    pos: int = c.base + int(num[1])

    if pos >= c.size:
        raise bad(f"startxref offset {int(num[1])} lies beyond the end of the file", end)

    raw: bytes = mm[pos : pos + 64]
    lead: int = len(raw) - len(raw.lstrip(ws))
    raw, pos = raw[lead:], pos + lead

    if raw.startswith(b"xref"):
        checked, wrong = check_xref_table(c, pos)

        if wrong:
            raise bad(
                f"{wrong} of {checked} checked xref entries do not point at their object", end
            )

    elif not obj_head_re.match(raw):
        near: int = mm.find(b"xref", max(c.base, pos - 32), pos + 32)

        if near != -1 and mm[near - 5 : near] != b"start":
            raise bad(f"startxref is off by {near - pos:+d} bytes from the xref table", end)

        raise bad("startxref points at neither an xref table nor an object", end)

    return end, "structure"


rtf_re: re.Pattern[bytes] = re.compile(rb"\\[\\{}]|[{}]")


def walk_rtf(c: context) -> WalkResult:
    depth: int = 0

    for m in rtf_re.finditer(c.mm, c.base):
        token: bytes = m.group()

        if token == b"{":
            depth += 1

        elif token == b"}":
            depth -= 1

            if depth == 0:
                return m.end(), "structure"

    raise cut("braces are still open at the end of the file")


junk_after_root: int = expat.errors.codes[expat.errors.XML_ERROR_JUNK_AFTER_DOC_ELEMENT]


def xml_parse(c: context, start: int, stop: int) -> list[str]:
    """Parse mm[start:stop] as a complete document; returns the parser or raises."""
    parser: expat.xmlparser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

    root: list[str] = []

    def first_element(name: str, attributes: XMLAttributes) -> None:
        root.append(name)
        parser.StartElementHandler = None  # only the root name is needed

    parser.StartElementHandler = first_element
    pos: int = start

    while pos < stop:
        parser.Parse(c.mm[pos : min(stop, pos + step)], False)
        pos += step

    parser.Parse(b"", True)
    return root


def walk_xml(c: context) -> WalkResult:
    start: int = 0 if c.mm[:3] == allowed_prefix["XML"] else c.base

    parser: expat.xmlparser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

    root: list[str] = []

    def first_element(name: str, attributes: XMLAttributes) -> None:
        root.append(name)
        parser.StartElementHandler = None

    parser.StartElementHandler = first_element
    pos: int = start
    final: bool = False

    try:
        while pos < c.size:
            parser.Parse(c.mm[pos : pos + step], False)
            pos += step

        final = True
        parser.Parse(b"", True)

    except expat.ExpatError as error:
        if error.code == junk_after_root:
            return start + parser.ErrorByteIndex, "structure"

        if final:
            raise cut(f"document ends early: {error}")

        if root:  # junk after the root may show up as another error code
            closing: bytes = b"</" + root[0].encode() + b">"
            at: int = c.mm.rfind(closing, start, c.size)

            if at != -1:
                try:
                    xml_parse(c, start, at + len(closing))
                    return at + len(closing), "structure"

                except (expat.ExpatError, ValueError):
                    pass

        raise bad(f"malformed xml: {error}")

    except ValueError:
        return None, "header"  # declared encoding expat cannot read

    return c.size, "structure"


def walk_ole(c: context) -> WalkResult:
    mm = c.mm

    need(c, c.base, 512, "header")

    shift: int = u16(c, c.base + 30)

    if shift not in (9, 12):
        raise bad("invalid sector size")

    sector: int = 1 << shift
    per: int = sector // 4

    nfat: int = u32(c, c.base + 44)
    nxt: int = u32(c, c.base + 68)
    ndifat: int = u32(c, c.base + 72)

    fat: list[int] = list(struct.unpack_from("<109I", mm, c.base + 76))[:nfat]
    walked: int = 0

    while len(fat) < nfat and nxt < 0xFFFFFFFA and walked < ndifat:
        pos: int = c.base + (nxt + 1) * sector

        need(c, pos, sector, "difat sector")

        vals: tuple[int, ...] = struct.unpack_from(f"<{per}I", mm, pos)

        fat += vals[:-1]
        nxt = vals[-1]
        walked += 1

    fat = fat[:nfat]
    last_used: int = -1

    for i, sec in enumerate(fat):
        pos: int = c.base + (sec + 1) * sector

        need(c, pos, sector, "fat sector")

        vals: tuple[int, ...] = struct.unpack_from(f"<{per}I", mm, pos)

        for j in range(per - 1, -1, -1):
            if vals[j] != 0xFFFFFFFF:
                last_used = max(last_used, i * per + j)
                break

    need(c, c.base + (last_used + 2) * sector, 0, "sectors listed in the fat")

    return None, "structure"

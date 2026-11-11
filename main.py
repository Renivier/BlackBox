"""Structural file classifier for every type in signatures.py.

Verdicts

    intact       no problem found at the depth that was reached
    truncated    the file ends before its own structure does
    corrupted    the structure is internally inconsistent
    padded       extra bytes after the point where the structure ends
    junked       extra bytes before the start of the structure
    unverified   nothing wrong found, but only the header (or just the magic) could be checked

    Other results: mismatch, unverifiable, unknown_type, empty

Every result carries a "depth", which says how much was actually verified:

    structure  every record / chunk / block was walked
    length     declared total size agrees with the real size (interior unchecked)
    ends       both ends verified (e.g. xz header and footer), interior unchecked
    header     only the header was verified
    trailer    only the table's trailer rule was applied
    magic      only the magic bytes matched

By default every check runs, including checksums and full decompression of gzip/bzip2/xz/zip, because truncation and corruption of those cannot be seen otherwise.

--fast reads only bounded windows through mmap, so cost does not grow with file size, at the price of weaker results (see "depth")

usage:

    python file_classifier.py file.ext folder other.ext
    python file_classifier.py --fast big_folder
"""

import argparse
import mmap
import pathlib
import re
import struct
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import Any, Literal, TypeAlias, TypedDict

from signatures import file_signatures
from types_walkers import registry
from types_walkers.archives import tar_checksum_ok
from types_walkers.common import allowed_prefix, context, cut, walkproblem, ws

Verdict: TypeAlias = Literal[
    "intact",
    "truncated",
    "corrupted",
    "padded",
    "junked",
    "unverified",
    "mismatch",
    "unverifiable",
    "unknown_type",
    "empty",
    "error",
]

Depth: TypeAlias = Literal[
    "structure",
    "length",
    "ends",
    "header",
    "trailer",
    "magic",
]

ProblemKind: TypeAlias = Literal["truncated", "corrupted"]

FileSignature: TypeAlias = dict[str, Any]
Probe: TypeAlias = Callable[[mmap.mmap, int], int | None]
Problem: TypeAlias = tuple[ProblemKind, str]


class ClassificationResult(TypedDict):
    verdict: Verdict
    type: str
    depth: Depth | Literal[""]
    flags: list[str]
    evidence: list[str]


trailing_ok: int = 8  # whitespace/zero bytes tolerated after the end
default_junk_window: int = 4096  # how far into the file to look for shifted magic
junk_windows: dict[str, int] = {"PDF": 65536, "ZIP": 65536}
priority: tuple[ProblemKind, ...] = ("truncated", "corrupted", "junked", "padded")


# extensions that legitimately have no magic bytes: "unverifiable", not a mismatch
no_magic_exts: set[str] = {
    ".txt",
    ".csv",
    ".tsv",
    ".json",
    ".md",
    ".log",
    ".ini",
    ".cfg",
    ".yaml",
    ".yml",
    ".toml",
    ".py",
    ".js",
    ".ts",
    ".html",
    ".htm",
    ".css",
    ".c",
    ".h",
    ".cpp",
    ".java",
    ".sh",
    ".bat",
    ".ps1",
}


# extension -> list of type names (a list: .rar, .o and .dylib map to several)
ext_map: dict[str, list[str]] = {}

for _name, _sig in file_signatures.items():
    for _ext in _sig["exts"]:
        ext_map.setdefault(_ext, []).append(_name)


def probe_tar(mm: mmap.mmap, size: int) -> int | None:
    """v7 tars have no 'ustar' magic: accept a valid first header checksum instead."""
    if size >= 512 and mm[0] != 0 and tar_checksum_ok(mm[:512]):
        return 0

    return None


def probe_xml(mm: mmap.mmap, size: int) -> int | None:
    """The xml declaration is optional: accept any document starting with a tag."""
    head: bytes = mm[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")

    if (head[:1] == b"<" and head[1:2].isalpha()) or head[:2] in (b"<!", b"<?"):
        return 0

    return None


probes: dict[str, Probe] = {"TAR": probe_tar, "XML": probe_xml}


# magics under 4 bytes are too weak to search for, so these types should get a longer pattern
junk_patterns: dict[str, re.Pattern[bytes]] = {
    "JPEG": re.compile(rb"\xff\xd8\xff[\xc0-\xfe]"),
    "GZIP": re.compile(rb"\x1f\x8b\x08[\x00\x02\x04\x08\x10]"),
    "BZIP2": re.compile(rb"BZh[1-9]1AY&SY"),
    "MP3 ID3": re.compile(rb"ID3[\x02-\x04]\x00"),
}


def find_base(mm: mmap.mmap, size: int, name: str, sig: FileSignature) -> int | None:
    """Where the structure starts: the magic's position minus its offset, or none."""
    offset: int = sig.get("offset", 0)

    for magic in sig["magic"]:
        if mm[offset : offset + len(magic)] == magic:
            return 0

    window: int = junk_windows.get(name, default_junk_window)
    best: int = -1
    pattern: re.Pattern[bytes] | None = junk_patterns.get(name)

    if pattern:
        found: re.Match[bytes] | None = pattern.search(mm, 1, min(size, window + 8))
        best = found.start() if found else -1

    else:
        for magic in sig["magic"]:
            if len(magic) < 4:
                continue

            found: int = mm.find(magic, offset + 1, min(size, window + offset + len(magic)))

            if found != -1 and (best == -1 or found - offset < best):
                best = found - offset

    if best >= 1:
        return best

    probe: Probe | None = probes.get(name)

    return probe(mm, size) if probe else None


def identify(mm: mmap.mmap, size: int, strict: bool = False) -> list[str]:
    names: list[str] = []

    for name, sig in file_signatures.items():
        offset: int = sig.get("offset", 0)

        for magic in sig["magic"]:
            if strict and len(magic) < 4:
                continue

            if mm[offset : offset + len(magic)] == magic:
                names.append(name)
                break

    return names


def result(
    verdict: Verdict,
    name: str = "",
    depth: Depth | Literal[""] = "",
    flags: list[str] | None = None,
    evidence: list[str] | None = None,
) -> ClassificationResult:
    return {
        "verdict": verdict,
        "type": name,
        "depth": depth,
        "flags": flags or [],
        "evidence": evidence or [],
    }


def analyze(
    mm: mmap.mmap, path: pathlib.Path, size: int, name: str, base: int, deep: bool
) -> ClassificationResult:
    sig: FileSignature = file_signatures[name]
    c: context = context(mm, base, size, deep, path)

    flags: list[str] = []
    evidence: list[str] = []
    problems: list[Problem] = []

    junk: int = base

    if allowed_prefix.get(name) and mm[:base] == allowed_prefix[name]:
        junk = 0

    if junk:
        flags.append("junked")
        evidence.append(f"{junk} unexpected bytes before the {name} data")

    end: int | None = None
    depth: Depth = "magic"
    walker = registry.get(name)

    try:
        if walker:
            end, depth = walker(c)

        elif "trailer" in sig:  # generic rule from the table
            depth = "trailer"
            tail: bytes = mm[max(0, size - sig["trailer_window"]) : size]
            exact: bool = sig["trailer_window"] == len(sig["trailer"])
            present: bool = tail == sig["trailer"] if exact else sig["trailer"] in tail

            if not present and sig.get("trailer_forced"):
                raise cut("required trailer is missing")

    except walkproblem as stop:
        problems.append((stop.kind, stop.message))
        end = stop.end
        depth = "structure" if walker else depth

    except (struct.error, IndexError, ValueError) as error:
        problems.append(("corrupted", f"malformed structure ({error})"))

    except Exception as error:  # a parser bug must not stop a folder scan
        problems.append(("corrupted", f"unexpected parser error ({type(error).__name__}: {error})"))

    kinds: set[str] = {kind for kind, _ in problems}
    evidence = [message for _, message in problems] + evidence

    if end is not None and "truncated" not in kinds:
        extra: int = size - end
        probe_bytes: bytes = mm[end : end + 4096]
        zeros: bool = not probe_bytes.strip(b"\x00") and extra <= 4096
        aligned: bool = zeros and extra < 512 and size % 512 == 0  # alignment padding

        if (
            extra > 0
            and not aligned
            and (extra > trailing_ok or mm[end : end + trailing_ok + 1].strip(ws))
        ):
            flags.append("padded")
            what: str = "zero bytes" if zeros else "bytes"
            evidence.append(f"{extra} {what} after the end of the {name} structure")

    allflags: list[str] = list(kinds) + flags

    # nothing found, but only the header (or less) was checked: do not claim "intact"
    verdict: Verdict = next(
        (k for k in priority if k in allflags),
        "unverified" if depth in ("magic", "header") else "intact",
    )

    return result(verdict, name, depth, allflags, evidence)


def classify(path: str | pathlib.Path, deep: bool = True) -> ClassificationResult:
    p: pathlib.Path = pathlib.Path(path)
    size: int = p.stat().st_size

    if size == 0:
        return result("empty", evidence=["file is 0 bytes"])

    ext: str = p.suffix.lower()

    with open(p, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        candidates: list[str] | None = ext_map.get(ext)

        if candidates is None:
            if ext in no_magic_exts:
                return result("unverifiable", evidence=[f"{ext} files have no magic bytes"])

            candidates = identify(mm, size, strict=True)

            if not candidates:
                return result(
                    "unknown_type",
                    evidence=[
                        f"extension {ext or '(none)'} is not in the table and no signature matched"
                    ],
                )

        for name in candidates:
            base: int | None = find_base(mm, size, name, file_signatures[name])

            if base is not None:
                return analyze(mm, p, size, name, base, deep)

        actual: list[str] = identify(mm, size)
        found: str = ", ".join(actual) if actual else "no known signature"

        return result(
            "mismatch",
            ", ".join(candidates),
            evidence=[f"extension {ext} claims {', '.join(candidates)}; content matches {found}"],
        )


def collect(targets: Iterable[str | pathlib.Path]) -> Iterator[pathlib.Path]:
    for target in targets:
        p: pathlib.Path = pathlib.Path(target)

        if p.is_dir():
            yield from sorted(f for f in p.rglob("*") if f.is_file())

        else:
            yield p


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="classify files as intact, truncated, corrupted, padded or junked"
    )
    parser.add_argument("paths", nargs="*")
    parser.add_argument(
        "--fast",
        action="store_true",
        help="read only the start and end of each file (skips checksums and decompression)",
    )

    args = parser.parse_args(argv)
    args.deep = not args.fast

    targets: list[str] = args.paths or [input("Enter a file or folder path: ").strip().strip('"')]
    counts: dict[str, int] = {}

    for f in collect(targets):
        try:
            r: ClassificationResult = classify(f, deep=args.deep)

        except OSError as error:
            r = result("error", evidence=[str(error)])

        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1

        label: str = f"{r['type']} [{r['depth']}]" if r["depth"] else r["type"]
        detail: str = f"  - {'; '.join(r['evidence'])}" if r["evidence"] else ""

        print(f"{r['verdict']:<12} {label:<34} {f}{detail}")

    if sum(counts.values()) > 1:
        print("\nsummary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main(sys.argv[1:])

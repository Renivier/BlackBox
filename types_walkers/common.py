"""Shared pieces for the types & walkers: the problem exception, the context and small helpers."""

import mmap
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Literal, TypeVar

T = TypeVar("T")
ProblemKind = Literal["truncated", "corrupted"]
step: int = 1 << 20
ws: bytes = b" \t\r\n\x00\x0c"
allowed_prefix: dict[str, bytes] = {"XML": b"\xef\xbb\xbf"}


class walkproblem(Exception):
    kind: ProblemKind
    message: str
    end: int | None

    def __init__(self, kind: ProblemKind, message: str, end: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.end = end


class context:
    mm: mmap.mmap
    base: int
    size: int
    deep: bool
    path: Path

    def __init__(self, mm: mmap.mmap, base: int, size: int, deep: bool, path: Path) -> None:
        self.mm = mm
        self.base = base
        self.size = size
        self.deep = deep
        self.path = path


def cut(message: str, end: int | None = None) -> walkproblem:
    return walkproblem("truncated", message, end)


def bad(message: str, end: int | None = None) -> walkproblem:
    return walkproblem("corrupted", message, end)


def need(c: context, pos: int, count: int, what: str) -> None:
    if pos + count > c.size:
        raise cut(f"{what} runs past the end of the file")


def rolling(c: context, func: Callable[[bytes, T], T], start: int, stop: int, value: T) -> T:
    while start < stop:
        piece: bytes = c.mm[start : min(stop, start + step)]
        value = func(piece, value)
        start += len(piece)
    return value


def u16(c: context, pos: int, order: str = "<") -> int:
    return struct.unpack_from(order + "H", c.mm, pos)[0]


def u32(c: context, pos: int, order: str = "<") -> int:
    return struct.unpack_from(order + "I", c.mm, pos)[0]


def stop_or_bad(c: context, pos: int, message: str) -> int:
    """A structure error at a record boundary: a small remainder is trailing junk,
    a large one means the structure itself broke."""
    if c.size - pos <= 4096:
        return pos
    raise bad(message)

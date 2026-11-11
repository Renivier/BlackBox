"""Damage test for file_classifier.py.

Takes a folder of VALID files, makes damaged copies of each one and reports what
file_classifier says about them:
    truncated  cut at 25 random points, at the half way mark, and one byte short
    padded     100 non-whitespace bytes appended
    junked     64 non-whitespace bytes prepended
    flips      40 single-bit flips at random positions

A format that reports "unverified" or "intact" for damage it cannot see (for
example a bit flip inside jpeg pixel data) is working as designed: those formats
carry no checksum to compare against.

usage:
    python mutation_test.py some_folder_of_valid_files
"""

import argparse
import collections
import pathlib
import random
import tempfile

import main as blackbox


def nonws(count):
    return bytes(random.choice(b"ABCDEFGHxyz0123456789!#") for _ in range(count))


def short(counts):
    total = sum(counts.values())
    parts = sorted(counts.items(), key=lambda item: -item[1])
    return " ".join(f"{name[:6]}:{number}" for name, number in parts) + f" /{total}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("folder")
    parser.add_argument(
        "--fast", action="store_true", help="use fast mode instead of the full checks"
    )
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    random.seed(args.seed)
    deep = not args.fast
    scratch = pathlib.Path(tempfile.mkdtemp())

    def verdict(data, ext):
        target = scratch / ("t" + ext)
        target.write_bytes(data)
        return blackbox.classify(target, deep=deep)["verdict"]

    print(
        f"{'file':22} {'intact':11} {'padded':11} {'junked':11} {'truncated (27 cuts)':34} bit flips (40)"
    )
    for f in sorted(pathlib.Path(args.folder).iterdir()):
        if not f.is_file() or f.stat().st_size < 2:
            continue
        data, ext, size = f.read_bytes(), f.suffix.lower(), f.stat().st_size
        cuts = [random.randint(1, size - 1) for _ in range(25)] + [size // 2, size - 1]
        trunc = collections.Counter(verdict(data[:cut], ext) for cut in cuts)
        flips = collections.Counter()
        for _ in range(40):
            damaged = bytearray(data)
            damaged[random.randrange(size)] ^= 1 << random.randrange(8)
            flips[verdict(bytes(damaged), ext)] += 1
        print(
            f"{f.name:22} {verdict(data, ext):11} {verdict(data + nonws(100), ext):11} "
            f"{verdict(nonws(64) + data, ext):11} {short(trunc):34} {short(flips)}"
        )


if __name__ == "__main__":
    main()

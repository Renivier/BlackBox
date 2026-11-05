from pathlib import Path
from a import file_signatures

no_magic_exts = {
    ".txt", ".csv", ".tsv", ".json", ".md", ".log", ".ini", ".cfg", ".yaml",
    ".yml", ".toml", ".py", ".js", ".ts", ".html", ".htm", ".css", ".c",
    ".h", ".cpp", ".java", ".sh", ".bat", ".ps1",
}

ext_map = {}
for _name, _sig in file_signatures.items():
    for _ext in _sig["exts"]:
        ext_map.setdefault(_ext, []).append(_name)

# How much of the file ever needs to be read.
head_size = max(
    s.get("offset", 0) + len(m)
    for s in file_signatures.values()
    for m in s["magic"]
)
tail_size = max(s.get("trailer_window", 0) for s in file_signatures.values())


def has_magic(head, sig):
    offset = sig.get("offset", 0)
    return any(head[offset:offset + len(m)] == m for m in sig["magic"])


def trailer_status(tail, sig):
    """True/False if the format has a checkable trailer, None if it has none."""
    trailer = sig.get("trailer")
    if trailer is None:
        return None

    window = sig["trailer_window"]
    tail = tail[-window:]

    if window == len(trailer):
        return tail == trailer
    return trailer in tail      


def read_edges(path):
    """Read only the start and end of the file, never the whole thing."""
    try:
        with open(path, "rb") as f:
            head = f.read(head_size)
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - tail_size))
            tail = f.read()
    except OSError as error:
        raise OSError(f"Could not read file: {error}") from error
    return head, tail


def validate(path):
    path = Path(path)
    ext = path.suffix.lower()     

    candidates = ext_map.get(ext)
    if candidates is None:
        status = "unverifiable" if ext in no_magic_exts else "unknown_extension"
        return {"status": status, "ext": ext}

    head, tail = read_edges(path)

    for name in candidates:
        sig = file_signatures[name]
        if not has_magic(head, sig):
            continue

        trailer = trailer_status(tail, sig)
        if trailer is False and sig.get("trailer_forced"):
            return {"status": "damaged", "type": name,
                    "reason": "magic matches but required trailer is missing"}
        return {"status": "match", "type": name, "trailer": trailer}

    actual = [n for n, s in file_signatures.items() if has_magic(head, s)]
    return {"status": "mismatch", "ext": ext, "claims": candidates, "actual": actual}


def main():
    path = input("Enter a file path: ").strip().strip('"')
    try:
        result = validate(path)
    except OSError as error:
        print(error)
        return

    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()





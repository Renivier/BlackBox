import inspect
import pickle
from pathlib import Path


class Checks:
    def __init__(self, file_object):
        self.file_object = file_object
        self.f = b""
        self.result_template = {"name": "", "match": False}

    def _load_data(self):
        try:
            with open(self.file_object, "rb") as f:
                self.f = f.read()
        except OSError as error:
            raise OSError(f"Could not read file: {error}") from error

    def _check_magic(self, name, definition):
        result = {"name": name, "match": False}
        offset = definition.get("offset", 0)
        magic_numbers = definition.get("magic", ())

        for magic_number in magic_numbers:
            size = len(magic_number)

            if self.f[offset:offset + size] == magic_number:
                result["match"] = True
                return result

        return result


    def pdf_check(self):
        result = self._check_magic("PDF", signatures["PDF"])

        if self.f.startswith(b"%PDF-") and b"%%EOF" in self.f[-1024:]:
            result["match"] = True

        return result

    def png_check(self):
        result = self._check_magic("PNG", signatures["PNG"])

        if self.f.startswith(b"\x89PNG\r\n\x1a\n") and self.f.endswith(b"IEND\xae\x42\x60\x82"):
            result["match"] = True

        return result

    def gif_check(self):
        result = self._check_magic("GIF", signatures["GIF"])

        if self.f.startswith((b"GIF87a", b"GIF89a")) and self.f.endswith(b";"):
            result["match"] = True

        return result

    def jpeg_check(self):
        result = self._check_magic("JPEG", signatures["JPEG"])

        if self.f.startswith(b"\xff\xd8\xff") and b"\xff\xd9" in self.f[-4096:]:
            result["match"] = True

        return result

    def zip_check(self):
        result = self._check_magic("ZIP", signatures["ZIP"])

        if self.f.startswith(b"PK\x03\x04") and b"PK\x05\x06" in self.f[65557:]:
            result["match"] = True

        return result

    def tar_check(self):
        result = self._check_magic("TAR", signatures["TAR"])

        if self.f[257:262] == b"ustar" and self.f[-1024:] == b"\x00" * 1024:
            result["match"] = True

        return result


with open("signatures.pkl", "rb") as f:
    signatures = pickle.load(f)


file = input("Enter a file path: ")
file_obj = Path(file)
obj = Checks(file_object=file_obj)
obj._load_data()

methods = inspect.getmembers(obj, predicate=inspect.ismethod)
compiled_result = {}


for name, definition in signatures.items():
    result = obj._check_magic(name, definition)
    compiled_result[result["name"]] = result["match"]


for name, method in methods:
    if name.endswith("_check") and name != "_check_magic":
        result = method()
        compiled_result[result["name"]] = result["match"]

for name, match in compiled_result.items():
    if match:
        print(f"{name}: {match}")


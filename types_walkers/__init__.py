"""Per-format structure walkers.

Every walker takes a context and returns (end, depth), or raises walkproblem.
The registry maps a type name from a.py to its walker.
Types without a walker (Photoshop, RAR 4, RAR 5, Mach-O, Mach-O Universal)
are matched on their magic bytes only.
"""

from functools import partial

from .archives import (
    walk_7z,
    walk_bzip2,
    walk_cab,
    walk_cpio,
    walk_gzip,
    walk_lz4,
    walk_tar,
    walk_xz,
    walk_zip,
    walk_zstd,
)
from .binaries import (
    walk_class,
    walk_dex,
    walk_elf,
    walk_pcap,
    walk_pcapng,
    walk_pe,
    walk_sqlite,
    walk_wasm,
)
from .documents import walk_ole, walk_pdf, walk_rtf, walk_xml
from .images import walk_bmp, walk_gif, walk_ico, walk_jpeg, walk_png, walk_tiff
from .media import walk_aiff, walk_boxes, walk_flac, walk_mp3, walk_ogg, walk_riff

registry = {
    "PNG": walk_png,
    "JPEG": walk_jpeg,
    "GIF": walk_gif,
    "BMP": walk_bmp,
    "ICO": walk_ico,
    "CUR": walk_ico,
    "TIFF": walk_tiff,
    "PDF": walk_pdf,
    "RTF": walk_rtf,
    "XML": walk_xml,
    "OLE Compound File": walk_ole,
    "ZIP": walk_zip,
    "GZIP": walk_gzip,
    "BZIP2": walk_bzip2,
    "XZ": walk_xz,
    "Zstandard": walk_zstd,
    "LZ4": walk_lz4,
    "TAR": walk_tar,
    "7-Zip": walk_7z,
    "CAB": walk_cab,
    "CPIO": walk_cpio,
    "WebP": walk_riff,
    "WAV": walk_riff,
    "AVI": walk_riff,
    "AIFF": walk_aiff,
    "MP4/ISO Base Media": partial(walk_boxes, required=b"moov"),
    "AVIF": partial(walk_boxes, required=b"meta"),
    "JPEG 2000": partial(walk_boxes, required=b"jp2c"),
    "Ogg": walk_ogg,
    "FLAC": walk_flac,
    "MP3 ID3": walk_mp3,
    "WebAssembly": walk_wasm,
    "PCAP": walk_pcap,
    "PCAPNG": walk_pcapng,
    "ELF": walk_elf,
    "Windows PE/DOS": walk_pe,
    "Java Class": walk_class,
    "SQLite": walk_sqlite,
    "Android DEX": walk_dex,
}

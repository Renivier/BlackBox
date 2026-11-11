# BlackBox

<h1 align="center">
  <img src="https://img.shields.io/badge/BlackBox-Static_Analysis-242424?style=for-the-badge&logo=python&logoColor=white" height="48" alt="BlackBox"/><br/>
  BlackBox
</h1>

<p align="center">
  <em>Don't trust the extension. Examine the evidence.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Early_Development-ff69b4?style=flat-square" />
  <img src="https://img.shields.io/badge/Language-Python-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Analysis-Static-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square" />
</p>

BlackBox is a static file analysis tool designed to identify file formats and examine their internal structures without executing them.

A file extension is a claim, not proof. A file named `document.pdf` is not necessarily a PDF, and a valid header does not necessarily mean the rest of the file is intact.

BlackBox examines the bytes themselves, compares them against known file signatures, and, where supported, walks the internal structure to identify inconsistencies.

The goal is to determine not only what a file appears to be, but also how much of its structure can actually be verified.

---

## Why BlackBox?

Files are often treated as trustworthy based on their names, extensions, or metadata.

These properties can be misleading.

A file may have:

- An incorrect extension.
- A valid header followed by corrupted data.
- Missing or incomplete structural components.
- Unexpected bytes before or after its actual contents.
- Incorrect internal size declarations.
- Damaged checksums or compression streams.

BlackBox approaches the problem from the binary level.

Rather than relying on a single signature check, it attempts to establish the structure of a file and determine whether its contents are consistent with the expected format.

## Philosophy

BlackBox follows three principles.

### 1. Examine, Don't Execute

BlackBox does not need to execute a file to inspect it.

Its analysis is based on binary data, structural definitions, metadata, and format-specific rules.

This makes it possible to investigate files without relying on their intended applications or execution environments.

### 2. Structure Matters

A matching magic number is useful evidence, but it is not proof of validity.

Consider a PNG file:

```text
PNG Signature
     |
     v
+------------+
| IHDR       |
+------------+
| IDAT       |
+------------+
| IDAT       |
+------------+
| IEND       |
+------------+
```

Finding the PNG signature establishes a possible format identification.

Examining its chunks, lengths, checksums, and ending provides considerably stronger evidence.

BlackBox therefore distinguishes between identifying a format and validating its structure.

### 3. Report What Was Actually Verified

A file should not be declared intact merely because no problem was detected.

The amount of analysis matters.

BlackBox records the depth of verification so that its results communicate what was actually examined rather than suggesting certainty where none exists.

---

## How It Works

The general analysis process is:

```text
                 Input File
                     |
                     v
              File Information
                     |
                     v
              Extension Lookup
                     |
                     v
              Signature Analysis
                     |
                     v
              Structure Detection
                     |
                     v
             Format Identification
                     |
                     v
             Structural Validation
                     |
          +----------+----------+
          |                     |
          v                     v
     Format Walker        Generic Checks
          |                     |
          +----------+----------+
                     |
                     v
               Result Analysis
                     |
                     v
              Classification
```

BlackBox uses memory-mapped files through Python's `mmap` module. This allows it to inspect file contents without first loading the entire file into a separate bytes object.

Format-specific walkers handle the structural analysis. Shared parsing utilities provide bounds checks, integer readers, and consistent error reporting.

---

## Classification

Every classification result contains five fields:

```python
{
    "verdict": "intact",
    "type": "PNG",
    "depth": "structure",
    "flags": [],
    "evidence": []
}
```

### Verdicts

| Verdict | Meaning |
|---|---|
| `intact` | No problem detected at the achieved verification depth. |
| `truncated` | The file ends before its structure is complete. |
| `corrupted` | An internal structural inconsistency was detected. |
| `padded` | Unexpected bytes were found after the structure. |
| `junked` | Unexpected bytes were found before the structure. |
| `unverified` | No problem was detected, but verification was limited. |
| `mismatch` | The extension and detected contents disagree. |
| `unverifiable` | The format cannot be identified reliably using available signatures. |
| `unknown_type` | No supported signature matched. |
| `empty` | The file contains no data. |
| `error` | The file could not be accessed or processed. |

### Verification Depth

| Depth | Meaning |
|---|---|
| `structure` | Internal records, chunks, blocks, or other components were examined. |
| `length` | Declared size was compared with actual size. |
| `ends` | Relevant file boundaries were checked. |
| `header` | Only the header was examined. |
| `trailer` | A generic trailer rule was applied. |
| `magic` | Only the file signature was matched. |

The distinction is intentional.

An `intact` result means no problem was found at the depth reached. It does not claim that every possible property of the file has been verified.

---

## Supported Formats

BlackBox currently recognizes a range of binary formats through its signature table.

### Images

- PNG
- JPEG
- GIF
- BMP
- TIFF
- JPEG 2000
- WebP
- AVIF
- ICO
- CUR
- Photoshop

### Documents

- PDF
- RTF
- XML
- OLE Compound File

### Archives and Compression

- ZIP
- GZIP
- 7-Zip
- RAR 4
- RAR 5
- BZIP2
- XZ
- Zstandard
- TAR
- CAB
- CPIO
- LZ4

### Executables and Binary Formats

- Windows PE/DOS
- ELF
- Mach-O
- Mach-O Universal
- Java Class
- WebAssembly
- Android DEX

### Databases and Packet Captures

- SQLite
- PCAP
- PCAPNG

### Audio and Video

- MP3
- FLAC
- Ogg
- AIFF
- WAV
- AVI
- MP4 / ISO Base Media

**Note:** Recognition and structural validation are separate capabilities. Formats without a registered structural walker currently receive signature-based identification rather than full structural validation. These include Photoshop, RAR, and Mach-O variants.

---

## Development

BlackBox is built around a collection of format-specific structure walkers.

The current implementation is divided into several modules:

```text
BlackBox/
|
+-- types_walkers/
|   |
|   +-- common.py
|   +-- archives.py
|   +-- binaries.py
|   +-- documents.py
|   +-- images.py
|   +-- media.py
|
+-- signatures.py
+-- main.py
+-- testing.py
+-- pyproject.toml
+-- poetry.lock
```

### Core Components

**`signatures.py`**

Contains the file signature definitions, associated extensions, offsets, and optional trailer information.

**`main.py`**

Handles file collection, identification, classification, structural analysis, and result generation.

**`types_walkers/common.py`**

Contains shared parsing utilities, structural context, bounds checking, and error handling.

**Format Walkers**

Each walker is responsible for examining the internal structure of a particular format or group of related formats.

The modules are separated by format families to keep the parsing logic manageable.

---

## Usage

### Requirements

- Python 3.10+
- Poetry

### Installation

Clone the repository:

```bash
git clone https://github.com/Renivier/BlackBox.git
cd BlackBox
```

Install the development environment:

```bash
poetry install
```

### Analyze a File

```bash
poetry run python main.py document.pdf
```

### Analyze Multiple Files

```bash
poetry run python main.py document.pdf archive.zip image.png
```

### Analyze a Directory

```bash
poetry run python main.py ./testing_files
```

BlackBox recursively collects files from the supplied directory.

### Fast Mode

```bash
poetry run python main.py --fast ./testing_files
```

By default, BlackBox performs deeper checks, including checksum verification and decompression where supported.

Fast mode uses bounded reads through memory mapping and skips expensive operations such as full decompression and certain checksum checks.

The trade-off is weaker verification. Consult the reported depth when interpreting its results.

---

## Goals

### Short-Term

- [x] Build a file signature database.
- [x] Implement extension-based identification.
- [x] Implement signature-based identification.
- [x] Detect extension and content mismatches.
- [x] Establish a shared structural parsing interface.
- [x] Implement format-specific walkers.
- [x] Introduce verification depth.
- [x] Detect truncation and unexpected trailing data.
- [ ] Build a comprehensive automated test suite.
- [ ] Improve error handling and edge-case coverage.

### Medium-Term

- [ ] Expand structural validation.
- [ ] Improve detection of malformed file structures.
- [ ] Improve checksum and integrity verification.
- [ ] Add more format-specific validation rules.
- [ ] Improve performance on large files.
- [ ] Expand test coverage with deliberately damaged samples.
- [ ] Improve evidence reporting.

### Long-Term

- [ ] More extensive binary analysis.
- [ ] Structural comparison between files.
- [ ] Detection of concealed or embedded content.
- [ ] Entropy and byte-distribution analysis.
- [ ] File modification and integrity analysis.
- [ ] Additional security-oriented indicators.
- [ ] More comprehensive forensic reporting.

---

## What BlackBox Is Not

BlackBox is not:

- An antivirus engine.
- A malware sandbox.
- A file recovery tool.
- A guarantee that a file is safe.
- A replacement for every format-specific validation tool.

Static structural analysis can identify inconsistencies and suspicious characteristics, but it cannot establish that a file is harmless.

A structurally valid executable can still contain malicious code.

---

## Project Status

<p align="center">
  <img src="https://img.shields.io/badge/Development-Active-ff69b4?style=flat-square" />
</p>

BlackBox is in early development.

The current focus is reliable file identification and structural validation. Additional analysis capabilities will be developed on top of these foundations.

The priority is correctness and meaningful evidence, not simply increasing the number of supported extensions.

---

## License

No license has been selected yet.

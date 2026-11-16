# file-integrity-monitor

A command line tool that establishes the integrity of file(s) using hash values to alert users when file(s) or a directory undergoes changes.

## Usage

Requires Python 3.11 or newer and [`py7zr`](https://pypi.org/project/py7zr/):

```bash
python3 -m pip install py7zr
python3 hashcheck.py <file/directory> [--analyze] [--detect-encryption]
```

The first scan of a path stores a baseline. Later scans report whether the path
changed and replace the baseline with the new state.

| Flag                  | Effect                                                                           |
| --------------------- | -------------------------------------------------------------------------------- |
| `--analyze`           | Also runs `binwalk -E -N` (entropy analysis) on each file and stores its output. |
| `--detect-encryption` | Also runs encryption detection on each file and stores the result.               |

Flags may appear before or after the path and are not counted as arguments.

### What a scan does

- **Hash:** SHA-256 of a file, or of an in-memory 7z archive of every file in a directory.
- **CRC32:** read from the same 7z archive for every file. A changed value prints
  `CRC mismatch for <file>`.
- **Content diff:** the text of every file (up to 1 MiB) is stored. When a file changes, a
  unified diff against its previous text is printed. In a directory scan the diff is printed
  for each changed file, named in `File content has changed! File: <name>`.
- **Multiple hashes:** MD5, SHA-256, SHA-512, BLAKE2b and BLAKE2s of every scanned file.

### Cache files

Written to a `cache/` directory next to `hashcheck.py`. Every cache is keyed by the full
path of the file (or directory, in `hashes.json`) and written atomically.

| File               | Contents                                                                         |
| ------------------ | -------------------------------------------------------------------------------- |
| `hashes.json`      | SHA-256 of each scanned file, or of the 7z archive of a scanned directory.       |
| `crc.json`         | CRC32 of each file.                                                              |
| `content.json`     | Text of each file. Non-UTF-8 files are stored as the `repr` of their bytes.      |
| `multihashes.json` | The five hashes per file, plus `analysis` and `encryption` when those flags ran. |

`content.json` holds a copy of every scanned file, so treat the cache directory as sensitive.

### Binwalk analysis (`--analyze`)

`binwalk` must be on `PATH`; if it is not, the entry is recorded as `binwalk not installed`
and the scan continues. If it fails, its exit code and stderr are recorded. The flags
`-E -N` are confirmed for binwalk 2.x. Binwalk 3.x is a rewrite whose flags were not
verified; adjust the command in `run_analysis` if needed. This is the only entropy
analysis in the tool.

### Encryption detection (`--detect-encryption`)

Uses only the standard library and reads at most the first 8 MiB of each file:

- **Signatures:** OpenPGP/GPG armor, PKCS#8 encrypted keys, OpenSSL `Salted__`, LUKS,
  PKCS#7/CMS (DER) enveloped and encrypted data, the encryption flag of the first ZIP entry,
  and the Windows NTFS encrypted (EFS) attribute.
- **Statistics per 4 KiB block:** chi-square byte uniformity with a confidence interval, a
  confidence interval on the mean byte, and the NIST SP 800-22 frequency, block frequency,
  runs and cumulative sums tests. A block is random-like only if all of them pass
  (a HEDGE-style combination, not a reproduction of the published tool).
- **Change points:** CUSUM over the per-block results locates where a file switches between
  structured and random-like regions (`regions` in the output).
- **Structure:** whether the size is a multiple of 8 or 16 bytes, and the zlib compression ratio.
- **Compressed formats:** gzip, bzip2, xz, 7-Zip, ZIP, RAR, Zstandard, PNG and JPEG signatures
  stop random-like data being reported as encrypted.

Statistics cannot separate encrypted data from truly random or strongly compressed data.
In testing, deflate and bzip2 output was distinguishable, but xz/LZMA output without its
magic bytes looked identical to encrypted data, so the verdict says "likely". Not implemented:
the NIST approximate-entropy test (an entropy measure), binary OpenPGP packet headers and
PEM-armored PKCS#7.

## Automated tests

Use Python 3.14 (the application's documented runtime):

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python tests/run_suite.py
```

With that environment activated, `python tests/run_suite.py` also runs the
complete suite. The runner works from any working directory when invoked by its
absolute path and exits with pytest's exit code. It prints verbose output and
replaces `pytest-output.txt`, `junit.xml`, and `summary.txt` under `tests/results/`.
Generated reports are ignored by Git; `.gitkeep` preserves the directory.
For focused debugging, run `.venv/bin/python -m pytest tests/test_files.py -v`.

Every application test copies `hashcheck.py` into its own pytest temp
directory and invokes it with the current Python interpreter. Pytest manages
temp directories using standard cleanup/retention policy. `tests/test_hashcheck.py`
calls the application's functions directly. Tests that need `binwalk` use a fake
executable, and tests that need random-looking data use a deterministic generator,
so the suite needs no extra tools and gives the same result on every run. The suite
uses the standard library with pytest and `py7zr`, and is suitable for Docker containers
(see the `Dockerfile`).

### Confirmed behavior and limitations

- Invalid argument counts and nonexistent paths print usage but exit with status
  zero. A nonexistent path also creates an empty cache. Three strict expected
  failures describe the desired nonzero exit behavior; separate passing tests
  check the current behavior.
- Directory hashes cover a 7z archive of files. Empty subdirectory
  additions/deletions are invisible. A strict expected failure describes desired
  detection of additions. File modifications are detected.
- The archive includes file timestamps, so a timestamp-only change can alter a
  directory hash. Individual file hashes cover contents only and ignore timestamp
  changes, despite the application's message mentioning metadata. Directory
  hashes should not be treated as portable content-only digests across systems.
- Malformed JSON and tested non-object cache values cause an uncaught exception
  and nonzero exit, leaving the cache untouched. A malformed `crc.json`,
  `content.json` or `multihashes.json` does the same, but `multihashes.json` is read
  after the baseline is saved, so that baseline is already updated when it fails.
  Invalid digest strings in an otherwise valid cache are treated as previous hashes
  and replaced as changes. Cache contents are not validated before use.
- A baseline created without stored content (for example by an older version) reports
  a change normally and prints `Not available` in place of a diff. Files over 1 MiB are
  never stored, so they never get a diff.
- Unreadable files cause an uncaught `PermissionError` when permissions are
  enforced.
- Detected modifications automatically replace the saved baseline. A following
  unchanged scan reports no change.

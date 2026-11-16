#!/usr/bin/env python3
# python hashcheck.py <file/directory> [--analyze] [--detect-encryption]
#   --analyze           : also run binwalk entropy analysis (if installed) and store its output
#   --detect-encryption : also run encryption detection (signatures, chi-square, NIST tests,
#                         CUSUM change points, compressibility) and store the result
# ----------------------------------------------------------------------
# Title    : File Integrity Monitor
# Authors  : Jadon Duff, Jacob Ewasko, Justin Bower
# Created  : 2026-10-23
# Updated  : 2026-10-30
# Class    : CYB3801 Intro to Cybersecurity
# Project  : Final
# Hardware : Verified Apple M5 Pro (64GB Memory), 
#            Verified AMD Ryzen 9 7940HX with Radeon Graphics (48 GB Memory)
# Software : Verified Python 3.14.3; Verified Python 3.13.13
# Runtime  : 0.02s
# ----------------------------------------------------------------------
# Description:
#   Monitors integrity of files and/or directories by computing and
#   saving hashes. Each scan also records a CRC32 and the stored content
#   of every file, so a change can be traced to the file and lines that
#   differ, and saves several hashes per file.
#
# Cache files (written to a cache/ directory next to this script):
#   hashes.json       SHA-256 of each scanned file, or of the 7z archive of a directory
#   crc.json          CRC32 of each file, read back from the 7z archive
#   content.json      text of each file (up to 1 MiB), used to print a diff after a change
#   multihashes.json  MD5, SHA-256, SHA-512, BLAKE2b and BLAKE2s of each file, plus the
#                     optional binwalk and encryption detection results
#
# Dependencies:
#   Required:
#     - Python 3.11+ (hashlib.file_digest is used for hashing)
#     - py7zr (third-party; pip install py7zr), used to build the 7z archive that
#       provides the CRC32 values and the directory hash
#     - Standard library only otherwise
#   Optional (only needed for --analyze):
#     - binwalk, found on PATH. If it is missing, the analysis entry is
#       recorded as "binwalk not installed" and the script continues.
#     - Command run: binwalk -E -N <file>
#         -E = entropy analysis, -N = no plot window (so it never blocks)
#     - These flags are confirmed for binwalk 2.x (EOL December 2025).
#       binwalk 3.x is a rewrite and its flags were NOT verified; if the
#       call fails there, the exit code and stderr are saved in
#       cache/multihashes.json. Check `binwalk -h` and adjust the command
#       list in run_analysis if needed.
#
# Notes:
#   - Directory hashes cover a 7z archive of the files, which includes file
#     timestamps and permissions, so a timestamp-only change alters the hash.
#   - content.json holds a copy of every scanned file (up to 1 MiB each), so
#     treat the cache directory as sensitive.
#   - --detect-encryption needs no external tools. It reads at most the first 8 MiB of
#     each file. Statistics cannot separate encrypted data from truly random or
#     strongly compressed data (in testing, xz/LZMA output without its magic bytes
#     looked identical to encrypted data), so the verdict says "likely".
#   - md5, blake2b and blake2s are listed in hashlib.algorithms_guaranteed, meaning
#     hashlib offers them on every platform. That list is not a runtime promise:
#     on a FIPS-mode system OpenSSL can refuse MD5, so hashlib.new("md5") may raise
#     an error there. blake2b/blake2s are built into Python itself, not OpenSSL.
#     Other algorithms (e.g. ripemd160, sm3) depend on the local OpenSSL build.
#
# References:
#   None
# ----------------------------------------------------------------------

# ---- Imports ---------------------------------------------------------
from collections import Counter
from collections.abc import Callable
from pathlib import Path
import difflib
import hashlib
import io
import json
import math
import os
import shutil
import stat
import struct
import subprocess
import sys
import zlib

# 7-Zip imports
from py7zr import SevenZipFile


# ---- Constants -------------------------------------------------------
USAGE = "python3 hashcheck.py <file/directory> [--analyze] [--detect-encryption]"
FLAGS = ("--analyze", "--detect-encryption")

CHUNK_SIZE = 65536
CRC_FILE = "crc.json"
CONTENT_FILE = "content.json"
DETAILS_FILE = "multihashes.json"

# Files larger than this are not stored in content.json, so no diff is shown for them
CONTENT_MAX_BYTES = 1024 * 1024

MULTI_ALGORITHMS = ("md5", "sha256", "sha512", "blake2b", "blake2s")


# ---- Helpers ---------------------------------------------------------
def save_json(path: Path, data: dict) -> None:
    """Saves a dictionary as a `.json` file without risking a half-written cache.

    The data is written to a temporary file next to `path`, which then replaces
    `path` in a single step, so an interrupted run cannot corrupt a baseline.

    Args:
        path (Path): The path of the `.json` file to write.
        data (dict): The dictionary to save.

    Returns:
        None.
    """
    temp_path = path.with_name(path.name + ".tmp")
    try:
        with open(temp_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
        os.replace(temp_path, path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def load_json(path: Path) -> dict:
    """Loads a `.json` cache, creating an empty one first if it does not exist.

    Args:
        path (Path): The path of the `.json` file to load.

    Returns:
        dict: The loaded contents.
    """
    if not path.is_file():
        save_json(path, dict())

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def handle_paths(path: str) -> tuple[Path, Path, dict]:
    """Converts a path string into three directory paths.

    Ingests the provided path parameter and returns a triplet (3-tuple)
    representing the user-provided directory, a path to the `.json` of cached hashes,
    and a dictionary containing the cached hashes.

    Args:
        path (str): The path to handle.

    Returns:
        tuple[Path, Path, dict]: A triplet of the user-provided Path, hashes Path, and hashes dictionary.
    """
    path = Path(path).resolve()

    self_dir = Path(__file__).resolve().parent
    sub_dir = self_dir / "cache"
    hash_path = sub_dir / "hashes.json"

    sub_dir.mkdir(parents=True, exist_ok=True)

    hashes_dict = load_json(hash_path)

    return path, hash_path, hashes_dict


def read_content(path: Path) -> str | None:
    """Reads a file so that two versions of it can be compared line by line.

    UTF-8 text is returned as text. Any other file is returned as the `repr`
    of its bytes so it can still be compared. A file larger than
    `CONTENT_MAX_BYTES` is not read and returns `None`.

    Args:
        path (Path): The path to the file to read.

    Returns:
        str | None: The content, or `None` if the file is too large.
    """
    with open(path, "rb") as file:
        data = file.read(CONTENT_MAX_BYTES + 1)

    if len(data) > CONTENT_MAX_BYTES:
        return None

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return repr(data)


def store_content(contentdict: dict, key: str, content: str | None) -> None:
    """Saves a file's content in the content cache, dropping any stale copy if it is `None`.

    Args:
        contentdict (dict): A dictionary of previously stored file contents.
        key (str): The path of the file.
        content (str | None): The current content of the file.

    Returns:
        None.
    """
    if content is None:
        contentdict.pop(key, None)
    else:
        contentdict[key] = content


def print_diff(old: str | None, new: str | None) -> None:
    """Prints a unified diff between the previous and current content of a file.

    Args:
        old (str | None): The previously stored content, or `None` if there is none.
        new (str | None): The current content, or `None` if it was not read.

    Returns:
        None.
    """
    print("Difference since last update:")
    if old is None or new is None:
        print("Not available: no content was stored for one of the two versions.")
        return

    # StringIO splits only on "\n", so unusual line separators are not treated as lines
    diff = difflib.unified_diff(
        io.StringIO(old).readlines(), io.StringIO(new).readlines(), fromfile="previous", tofile="current"
    )
    for line in diff:
        if line.endswith("\n"):
            print(line, end="")
        else:
            print(line)
            print("\\ No newline at end of file")


def compress(entries: list[tuple[Path, str]]) -> io.BytesIO:
    """Builds an in-memory 7z archive.

    Args:
        entries (list[tuple[Path, str]]): Pairs of a file path and the name it gets inside the archive.

    Returns:
        io.BytesIO: The archive, positioned at the start.
    """
    buffer = io.BytesIO()
    with SevenZipFile(buffer, "w") as zip_file:
        for path, arcname in entries:
            print("Compressing", path)
            zip_file.write(path, arcname=arcname)

    buffer.seek(0)
    return buffer


def review_crcs(
    buffer: io.BytesIO, base_dir: Path, crcdict: dict, on_member: Callable[[str, str], None] | None = None
) -> None:
    """Prints the CRC32 of every archive member, flags changes and updates the CRC cache.

    CRC values are cached under the member's full path (`base_dir` joined with its
    archive name), the same way `hashes.json` is keyed, so files with the same name in
    different directories do not collide.

    Args:
        buffer (io.BytesIO): The 7z archive to read.
        base_dir (Path): The directory the archive names are relative to.
        crcdict (dict): A dictionary of previous CRC32 values, updated in place.
        on_member (Callable[[str, str], None] | None): Called with the full path and archive
            name of each member right after its CRC32 is handled.

    Returns:
        None.
    """
    buffer.seek(0)
    with SevenZipFile(buffer, "r") as zip_file:
        for member in zip_file.list():
            key = str(base_dir / member.filename)

            # Using .crc32 and handling cases where a directory might have a None CRC
            crc_value = hex(member.crc32) if member.crc32 is not None else "N/A"
            print(f"File: {member.filename} | CRC32: {crc_value}")

            # Check if the crc values have changed
            if key in crcdict and crc_value != crcdict[key]:
                print(f"CRC mismatch for {member.filename}")

            # Update crc values
            crcdict[key] = crc_value

            if on_member is not None:
                on_member(key, member.filename)


# ---- Checks ----------------------------------------------------------
def check_file(target_path: Path, hash_path: Path, cache: dict) -> None:
    """Handles hashes for a single file.

    Takes a target file path, hashes cache path and a cache. Handles hash checking logic
    for a single file using `json` and the `sha256` hashing algorithm. Also checks the
    file's CRC32 and, if it changed, prints a diff against its previously stored content.

    Args:
        target_path (Path): The path to the desired file to check.
        hash_path (Path): The path to the hash cache.
        cache (dict): A dictionary of previous file/directory hashes.
    
    Returns:
        None.
    """
    print(target_path)
    with open(target_path, "rb") as file:
        filehash = hashlib.file_digest(file, "sha256")
    print(f"File Hash is: {filehash.hexdigest()}")

    # Find previous crc and content if available
    crc_path = hash_path.with_name(CRC_FILE)
    content_path = hash_path.with_name(CONTENT_FILE)
    crcdict = load_json(crc_path)
    contentdict = load_json(content_path)

    # Find new crc and compare with previous to see if changed
    buffer = compress([(target_path, target_path.name)])
    review_crcs(buffer, target_path.parent, crcdict)

    filecontent = read_content(target_path)

    # New file path provided
    if str(target_path) not in cache:
        print("File has not been checked before; adding to cache.")
        cache[str(target_path)] = filehash.hexdigest()

    # File already exists in cache
    else:
        old_hash = cache[str(target_path)]
        if old_hash == filehash.hexdigest():
            print("File has NOT changed.")
        else:
            print(f"File has changed! Previous hash was: {old_hash}")
            print_diff(contentdict.get(str(target_path)), filecontent)
            cache[str(target_path)] = filehash.hexdigest()
            print("The contents or metadata of the file has been verified to have changed from its past scan. Proceed with caution.")

    store_content(contentdict, str(target_path), filecontent)

    print("Running the hashcheck tool did not run or execute files and only verified the integrity of the specified file or directory.")

    # Save file
    save_json(hash_path, cache)
    save_json(crc_path, crcdict)
    save_json(content_path, contentdict)


def check_dir(target_path: Path, hash_path: Path, cache: dict) -> None:
    """Handles hashes for a directory.

    Takes a target directory path, hashes cache path and a cache. Handles hash checking logic
    for a directory using `json`, `7z`, and the `sha256` hashing algorithm. Also checks the
    CRC32 of every file and prints a diff for each file whose content has changed.

    Args:
        target_path (Path): The path to the desired directory to check.
        hash_path (Path): The path to the hash cache.
        cache (dict): A dictionary of previous file/directory hashes.
    
    Returns:
        None.
    """
    entries = [
        (file, file.relative_to(target_path).as_posix())
        for file in sorted(target_path.rglob("*"))
        if file.is_file()
    ]
    buffer = compress(entries)
    contents = {str(file): read_content(file) for file, _ in entries}

    # Find previous crc and content if available
    crc_path = hash_path.with_name(CRC_FILE)
    content_path = hash_path.with_name(CONTENT_FILE)
    crcdict = load_json(crc_path)
    contentdict = load_json(content_path)

    def review_content(key: str, name: str) -> None:
        # Compare the stored content of one file with its current content
        if key not in contents:
            return

        old_content = contentdict.get(key)
        if old_content is not None and contents[key] is not None and old_content != contents[key]:
            print(f"File content has changed! File: {name}")
            print_diff(old_content, contents[key])
            print()

        store_content(contentdict, key, contents[key])

    review_crcs(buffer, target_path, crcdict, review_content)

    buffer.seek(0)
    dirhash = hashlib.file_digest(buffer, "sha256").hexdigest()
    print(f"Directory Hash is: {dirhash}")

    # New dir path provided
    if str(target_path) not in cache:
        print("Directory has not been checked before; adding to cache.")
        cache[str(target_path)] = dirhash

    # Dir already exists in cache
    else:
        old_hash = cache[str(target_path)]
        if old_hash == dirhash:
            print("Directory has NOT changed.")
        else:
            print(f"Directory has changed! Previous hash was: {old_hash}")
            cache[str(target_path)] = dirhash
            print("The contents or metadata of the directory has been verified to have changed from its past scan. Proceed with caution.")

    print("Running the hashcheck tool did not run or execute files and only verified the integrity of the specified file or directory.")

    # Save file
    save_json(hash_path, cache)
    save_json(crc_path, crcdict)
    save_json(content_path, contentdict)


# ---- Multi-hash and binwalk analysis ---------------------------------
def compute_hashes(target_path: Path) -> dict:
    """Computes several hashes of one file in a single read pass.

    Args:
        target_path (Path): The path to the file to hash.

    Returns:
        dict: Maps each algorithm name in `MULTI_ALGORITHMS` to its hex digest.
    """
    hashers = {name: hashlib.new(name) for name in MULTI_ALGORITHMS}
    with open(target_path, "rb") as file:
        chunk = file.read(CHUNK_SIZE)
        while chunk:
            for hasher in hashers.values():
                hasher.update(chunk)
            chunk = file.read(CHUNK_SIZE)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def run_analysis(target_path: Path) -> dict:
    """Runs `binwalk` entropy analysis on one file, failing gracefully if unavailable.

    Uses `-E` (entropy) and `-N` (no plot window, so the script never blocks).

    Args:
        target_path (Path): The path to the file to analyze.

    Returns:
        dict: A `status` and, when binwalk ran, its `output` and `stderr`.
    """
    if shutil.which("binwalk") is None:
        return {"status": "binwalk not installed"}
    try:
        proc = subprocess.run(["binwalk", "-E", "-N", str(target_path)], capture_output=True, text=True)
    except OSError as error:
        return {"status": f"failed to run: {error}"}
    return {
        "status": "ok" if proc.returncode == 0 else f"exit code {proc.returncode}",
        "output": proc.stdout,
        "stderr": proc.stderr,
    }


# ---- Encryption detection --------------------------------------------
# Methods used (all standard library; no entropy is calculated here, the only
# entropy analysis in this tool is the `binwalk -E` call above):
#   1. Signatures    : magic numbers and flags of known encrypted formats
#   2. Chi-square    : byte-frequency uniformity with a two-sided confidence
#                      interval, plus a confidence interval on the mean byte value
#   3. NIST SP 800-22: frequency (monobit), frequency within a block, runs and
#                      cumulative sums tests, applied per block
#   4. HEDGE-style   : a block is "random-like" only if chi-square, the mean
#                      interval and all four NIST tests pass; known compressed
#                      format signatures stop compressed files being called encrypted
#   5. CUSUM         : change-point detection over the per-block results to locate
#                      transitions between structured and random-like regions
#   6. Structure     : block-size alignment and zlib compressibility
# Not implemented on purpose: the NIST approximate-entropy test (it is an entropy
# measure, and binwalk is the only entropy analysis allowed), binary OpenPGP
# packet headers (a single leading byte is too weak to be a reliable signature)
# and PEM-armored PKCS#7 (it would need base64 decoding).
DETECT_MAX_BYTES = 8 * 1024 * 1024  # analyze at most the first 8 MiB of a file
DETECT_BLOCK_SIZE = 4096            # bytes per block (16 expected hits per byte value)
DETECT_MIN_BYTES = 1280             # chi-square needs an expected count of 5+ per value
DETECT_ALPHA = 0.001                # per-block significance level
DETECT_FRACTION = 0.95              # fraction of random-like blocks to call a file random-like
DETECT_ZLIB_RATIO = 0.98            # zlib ratio at or above this counts as incompressible
DETECT_FREQ_CHUNK = 64              # bytes per chunk (M = 512 bits) for the block-frequency test
DETECT_CUSUM_CRIT = 1.358           # approx. 5% critical value for the change-point statistic
DETECT_MIN_SEGMENT = 4              # smallest region (in blocks) a change point may create

# Formats that are encrypted by definition: (magic, name, latest offset it may start at)
ENCRYPTED_SIGNATURES = (
    (b"-----BEGIN PGP MESSAGE-----", "OpenPGP/GPG armored message", 256),
    (b"-----BEGIN ENCRYPTED PRIVATE KEY-----", "PKCS#8 encrypted private key (PEM)", 256),
    (b"Salted__", "OpenSSL enc output", 0),
    (b"LUKS\xba\xbe", "LUKS encrypted volume", 0),
    # DER OIDs 1.2.840.113549.1.7.3 (envelopedData) and .7.6 (encryptedData)
    (bytes.fromhex("2a864886f70d010703"), "PKCS#7/CMS envelopedData (DER)", 64),
    (bytes.fromhex("2a864886f70d010706"), "PKCS#7/CMS encryptedData (DER)", 64),
)

# Compressed or container formats, used only to avoid calling compressed data encrypted
COMPRESSED_SIGNATURES = (
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip (its contents may still be encrypted)"),
    (b"PK\x03\x04", "ZIP"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"(\xb5/\xfd", "Zstandard"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
)


def _igamc(a: float, x: float) -> float:
    """Upper regularized incomplete gamma function Q(a, x).

    Series expansion for x < a + 1, Lentz continued fraction otherwise
    (the standard Numerical Recipes split). Used for chi-square p-values.

    Args:
        a (float): The shape parameter.
        x (float): The upper limit.

    Returns:
        float: Q(a, x).
    """
    if x <= 0.0:
        return 1.0
    log_prefix = -x + a * math.log(x) - math.lgamma(a)
    if x < a + 1.0:
        term = total = 1.0 / a
        ap = a
        for _ in range(10000):
            ap += 1.0
            term *= x / ap
            total += term
            if abs(term) < abs(total) * 1e-15:
                break
        return 1.0 - total * math.exp(log_prefix)

    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 10000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return math.exp(log_prefix) * h


def _normal_cdf(x: float) -> float:
    """Standard normal cumulative distribution function."""
    return 0.5 * math.erfc(-x / math.sqrt(2.0))


def chi_square_bytes(data: bytes) -> dict:
    """Chi-square test of byte-frequency uniformity (255 degrees of freedom).

    Also tests the mean byte value against its confidence interval (uniform
    bytes have mean 127.5 and standard deviation sqrt((256^2 - 1) / 12)).

    Args:
        data (bytes): The bytes to test (at least `DETECT_MIN_BYTES`).

    Returns:
        dict: The chi-square statistic and p-value, and the mean byte and its p-value.
    """
    n = len(data)
    expected = n / 256.0
    counts = Counter(data)
    chi2 = sum((counts.get(value, 0) - expected) ** 2 for value in range(256)) / expected
    std_error = math.sqrt((256 ** 2 - 1) / 12.0) / math.sqrt(n)
    mean = sum(data) / n
    return {
        "chi_square": chi2,
        "chi_square_p": _igamc(127.5, chi2 / 2.0),
        "mean_byte": mean,
        "mean_byte_p": math.erfc(abs(mean - 127.5) / std_error / math.sqrt(2.0)),
    }


def _monobit_p(ones: int, n: int) -> float:
    """NIST SP 800-22 frequency (monobit) test p-value."""
    s_obs = abs(2 * ones - n) / math.sqrt(n)
    return math.erfc(s_obs / math.sqrt(2.0))


def _block_frequency_p(block_ones: list, m: int) -> float:
    """NIST SP 800-22 frequency-within-a-block test p-value (`block_ones` = ones per m-bit block)."""
    chi2 = 4.0 * m * sum((ones / m - 0.5) ** 2 for ones in block_ones)
    return _igamc(len(block_ones) / 2.0, chi2 / 2.0)


def _runs_p(ones: int, runs: int, n: int) -> float:
    """NIST SP 800-22 runs test p-value (0.0 if the frequency pre-test fails)."""
    pi = ones / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return 0.0
    return math.erfc(abs(runs - 2.0 * n * pi * (1.0 - pi)) / (2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)))


def _cusum_p(z: int, n: int) -> float:
    """NIST SP 800-22 cumulative sums test p-value for maximal excursion `z`."""
    z = max(z, 1)
    root_n = math.sqrt(n)
    first = sum(
        _normal_cdf((4 * k + 1) * z / root_n) - _normal_cdf((4 * k - 1) * z / root_n)
        for k in range(math.floor((-n / z + 1) / 4), math.floor((n / z - 1) / 4) + 1)
    )
    second = sum(
        _normal_cdf((4 * k + 3) * z / root_n) - _normal_cdf((4 * k + 1) * z / root_n)
        for k in range(math.floor((-n / z - 3) / 4), math.floor((n / z - 1) / 4) + 1)
    )
    return 1.0 - first + second


def _walk_table(msb_first: bool) -> list:
    """Per-byte (sum, max prefix, min prefix) of the +1/-1 bit walk, for a fast cusum."""
    table = []
    for value in range(256):
        bits = [(value >> shift) & 1 for shift in (range(7, -1, -1) if msb_first else range(8))]
        total, high, low = 0, -9, 9
        for bit in bits:
            total += 1 if bit else -1
            high, low = max(high, total), min(low, total)
        table.append((total, high, low))
    return table


_WALK_FORWARD = _walk_table(True)
_WALK_BACKWARD = _walk_table(False)  # bits of a reversed sequence read LSB first


def _max_excursion(data: bytes, table: list) -> int:
    """Largest absolute partial sum of the +1/-1 bit walk over `data`."""
    cur, best = 0, 0
    for byte in data:
        total, high, low = table[byte]
        best = max(best, cur + high, -(cur + low))
        cur += total
    return best


def nist_tests(block: bytes) -> dict:
    """Runs four NIST SP 800-22 tests on one block of bytes.

    Tests: frequency (monobit), frequency within a block (M = 512 bits),
    runs, and cumulative sums (forward and backward, the smaller p-value is kept).

    Args:
        block (bytes): The bytes to test (at least `DETECT_MIN_BYTES`).

    Returns:
        dict: Maps test name to p-value.
    """
    n = len(block) * 8
    value = int.from_bytes(block, "big")
    ones = value.bit_count()
    transitions = (value ^ (value >> 1)) & ((1 << (n - 1)) - 1)
    chunk_ones = [
        int.from_bytes(block[i:i + DETECT_FREQ_CHUNK], "big").bit_count()
        for i in range(0, len(block) - DETECT_FREQ_CHUNK + 1, DETECT_FREQ_CHUNK)
    ]
    forward = _cusum_p(_max_excursion(block, _WALK_FORWARD), n)
    backward = _cusum_p(_max_excursion(block[::-1], _WALK_BACKWARD), n)
    return {
        "frequency": _monobit_p(ones, n),
        "block_frequency": _block_frequency_p(chunk_ones, DETECT_FREQ_CHUNK * 8),
        "runs": _runs_p(ones, transitions.bit_count() + 1, n),
        "cumulative_sums": min(forward, backward),
    }


def is_random_like(block: bytes) -> bool:
    """HEDGE-style check: chi-square, mean interval and four NIST tests must all pass.

    The chi-square p-value is two-sided (too uniform is as suspicious as too lumpy).

    Args:
        block (bytes): The bytes to test.

    Returns:
        bool: True if every test passes at `DETECT_ALPHA`.
    """
    stats = chi_square_bytes(block)
    return (
        DETECT_ALPHA / 2 <= stats["chi_square_p"] <= 1 - DETECT_ALPHA / 2
        and stats["mean_byte_p"] >= DETECT_ALPHA
        and all(p >= DETECT_ALPHA for p in nist_tests(block).values())
    )


def find_change_points(flags: list) -> list:
    """Binary-segmentation CUSUM change-point detection over per-block 0/1 flags.

    For a segment, the cumulative sum of (flag - mean) peaks where the mean shifts.
    The peak is scaled by sigma * sqrt(n) and kept when it exceeds the ~5% critical
    value of the Brownian-bridge supremum, both sides are at least
    `DETECT_MIN_SEGMENT` blocks and their means differ by 0.5 or more.

    Args:
        flags (list): One 0/1 value per block (1 = random-like).

    Returns:
        list: Sorted block indexes where a new region starts.
    """
    def split(lo: int, hi: int) -> list:
        n = hi - lo
        if n < 2 * DETECT_MIN_SEGMENT:
            return []
        part = flags[lo:hi]
        mean = sum(part) / n
        sigma = math.sqrt(sum((x - mean) ** 2 for x in part) / n)
        if sigma == 0.0:
            return []
        running, best, best_k = 0.0, 0.0, -1
        for k, x in enumerate(part[:-1]):
            running += x - mean
            if abs(running) > best:
                best, best_k = abs(running), k
        cut = lo + best_k + 1
        left, right = flags[lo:cut], flags[cut:hi]
        if (
            best / (sigma * math.sqrt(n)) < DETECT_CUSUM_CRIT
            or len(left) < DETECT_MIN_SEGMENT
            or len(right) < DETECT_MIN_SEGMENT
            or abs(sum(left) / len(left) - sum(right) / len(right)) < 0.5
        ):
            return []
        return split(lo, cut) + [cut] + split(cut, hi)

    return split(0, len(flags))


def detect_signatures(head: bytes, path: Path) -> tuple[list, list]:
    """Looks for encrypted-format and compressed-format signatures.

    Besides magic numbers this checks the encrypted flag (bit 0) in the first ZIP
    local file header and, on Windows, the NTFS encrypted (EFS) file attribute.
    Only the first ZIP entry is inspected.

    Args:
        head (bytes): The first bytes of the file.
        path (Path): The file path (for the EFS attribute).

    Returns:
        tuple[list, list]: Names of encrypted-format matches and compressed-format matches.
    """
    encrypted = [
        name for magic, name, offset in ENCRYPTED_SIGNATURES
        if magic in head[:offset + len(magic)]
    ]
    compressed = [name for magic, name in COMPRESSED_SIGNATURES if head.startswith(magic)]
    if head.startswith(b"PK\x03\x04") and len(head) >= 8 and struct.unpack_from("<H", head, 6)[0] & 1:
        encrypted.append("ZIP entry with encryption flag set")
        compressed = [name for name in compressed if name != "ZIP"]
    if getattr(path.stat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_ENCRYPTED:
        encrypted.append("NTFS EFS encrypted file attribute")
    return encrypted, compressed


def detect_encryption(target_path: Path) -> dict:
    """Combines signature, statistical, change-point and structural checks for one file.

    Only the first `DETECT_MAX_BYTES` bytes are analyzed. Statistical tests run on
    whole `DETECT_BLOCK_SIZE` blocks (a trailing partial block is skipped; a file
    smaller than one block is tested as a single block if it has at least
    `DETECT_MIN_BYTES`). Statistics cannot tell encrypted data from strongly
    compressed or truly random data, so the verdict is worded accordingly.

    Args:
        target_path (Path): The path to the file to inspect.

    Returns:
        dict: signatures, block alignment, compressibility, statistics, regions and a verdict.
    """
    size = target_path.stat().st_size
    with open(target_path, "rb") as file:
        data = file.read(DETECT_MAX_BYTES)
    encrypted_sigs, compressed_sigs = detect_signatures(data[:4096], target_path)

    result = {
        "size_bytes": size,
        "bytes_analyzed": len(data),
        "signatures": {"encrypted": encrypted_sigs, "compressed": compressed_sigs},
        "block_alignment": {"multiple_of_16": size % 16 == 0, "multiple_of_8": size % 8 == 0},
        "compressibility": None,
        "statistics": None,
        "regions": [],
    }

    fraction = None
    if len(data) >= DETECT_MIN_BYTES:
        sample = data[:1024 * 1024]
        ratio = len(zlib.compress(sample, 9)) / len(sample)
        result["compressibility"] = {
            "zlib_ratio": ratio,
            "incompressible": ratio >= DETECT_ZLIB_RATIO,
        }

        starts = range(0, len(data) - DETECT_BLOCK_SIZE + 1, DETECT_BLOCK_SIZE)
        blocks = [data[i:i + DETECT_BLOCK_SIZE] for i in starts] or [data]
        flags = [1 if is_random_like(block) else 0 for block in blocks]
        whole = chi_square_bytes(data)
        fraction = sum(flags) / len(flags)
        result["statistics"] = {
            "chi_square": whole["chi_square"],
            "chi_square_p": whole["chi_square_p"],
            "mean_byte": whole["mean_byte"],
            "blocks": len(blocks),
            "random_like_blocks": sum(flags),
            "random_like_fraction": fraction,
        }

        edges = [0] + find_change_points(flags) + [len(flags)]
        result["regions"] = [
            {
                "start_byte": lo * DETECT_BLOCK_SIZE,
                "end_byte": min(hi * DETECT_BLOCK_SIZE, len(data)),
                "random_like": sum(flags[lo:hi]) / (hi - lo) >= 0.5,
            }
            for lo, hi in zip(edges, edges[1:])
        ]

    if encrypted_sigs:
        result["verdict"] = "encrypted (known signature: " + ", ".join(encrypted_sigs) + ")"
    elif fraction is None:
        result["verdict"] = "inconclusive (file too small for statistical tests)"
    elif fraction >= DETECT_FRACTION:
        if compressed_sigs:
            result["verdict"] = "random-like data, but a compressed-format signature is present: likely compressed (" + ", ".join(compressed_sigs) + ")"
        else:
            result["verdict"] = "likely encrypted (or random or strongly compressed data; statistics cannot separate these)"
    elif len({region["random_like"] for region in result["regions"]}) > 1:
        result["verdict"] = "mixed: random-like and structured regions (see regions)"
    elif fraction < 0.5:
        result["verdict"] = "no sign of encryption (structured or compressed data)"
    else:
        result["verdict"] = "inconclusive (partly random-like, see statistics)"
    return result


# ---- Details ---------------------------------------------------------
def record_details(target_path: Path, hash_path: Path, analyze: bool = False, detect: bool = False) -> None:
    """Stores multi-hash (and optional analysis) data for a file or each file in a directory.

    Writes `cache/multihashes.json` beside the existing `hashes.json`. Each entry holds
    that file's hashes and, if requested, the binwalk output and the encryption detection
    result, so they stay together.

    Args:
        target_path (Path): The user-provided file or directory.
        hash_path (Path): The path to the existing hash cache (used to locate `cache/`).
        analyze (bool): Whether to run `binwalk` on each file.
        detect (bool): Whether to run `detect_encryption` on each file.

    Returns:
        None.
    """
    details_path = hash_path.with_name(DETAILS_FILE)
    details = load_json(details_path)

    if target_path.is_file():
        files = [target_path]
    else:
        files = sorted(file for file in target_path.rglob("*") if file.is_file())

    for file_path in files:
        entry = {"hashes": compute_hashes(file_path)}
        if analyze:
            entry["analysis"] = {"binwalk": run_analysis(file_path)}
        if detect:
            entry["encryption"] = detect_encryption(file_path)
            print(f"Encryption detection for {file_path}: {entry['encryption']['verdict']}")
        details[str(file_path)] = entry

    save_json(details_path, details)


# ---- Main ------------------------------------------------------------
def main(argv: list[str]) -> None:
    """Runs the tool on the command line arguments (without the program name).

    Args:
        argv (list[str]): The path to check and any of `FLAGS`.

    Returns:
        None.
    """
    # Keep printing even if a file's text cannot be encoded by the console
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")

    analyze = "--analyze" in argv
    detect = "--detect-encryption" in argv
    args = [arg for arg in argv if arg not in FLAGS]

    if len(args) == 1:
        target_path, hash_path, cache = handle_paths(args[0])

        if target_path.is_file():
            check_file(target_path, hash_path, cache)
            record_details(target_path, hash_path, analyze, detect)
        elif target_path.is_dir():
            check_dir(target_path, hash_path, cache)
            record_details(target_path, hash_path, analyze, detect)
        else:
            print(f"Illegal Argument: You passed {target_path} while only valid files or directories are accepted.\nUsage:\n\t{USAGE}")

    else:
        print(f"Illegal Argument(s): You passed {len(args)} arguments while only 1 is accepted.\nUsage:\n\t{USAGE}")


if __name__ == "__main__":
    main(sys.argv[1:])

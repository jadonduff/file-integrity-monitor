#!/usr/bin/env python3
# python hashcheck.py <file/directory> [--analyze]
#   --analyze : also run binwalk entropy analysis (if installed) and store its output
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
#   saving hashes.
#
# Dependencies:
#   Required:
#     - Python 3.11+ (hashlib.file_digest is used in check_file)
#     - py7zr (third-party; pip install py7zr), used for the CRC32 checks
#     - Standard library only otherwise (hashlib, json, pathlib, shutil,
#       subprocess, sys, io, os)
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
#   - MD5 may raise an error on systems running in FIPS mode.
#   - blake2b/blake2s/md5 are guaranteed by hashlib; other algorithms
#     depend on the local OpenSSL build.
#
# References:
#   None
# ----------------------------------------------------------------------

# ---- Imports ---------------------------------------------------------
# from zipfile import ZipFile, ZIP_DEFLATED
# 7-Zip imports
from py7zr import SevenZipFile
from py7zr.helpers import calculate_crc32


from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import io
import os


# ---- Helpers ---------------------------------------------------------
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
    # crc_path = sub_dir / "crc.json"

    sub_dir.mkdir(parents=True, exist_ok=True)

    if not hash_path.is_file():
        with open(hash_path, "w", encoding="utf-8") as file:
            json.dump(dict(), file, indent=4)

    with open(hash_path, "r") as file:
        hashes_dict = json.load(file)

    return path, hash_path, hashes_dict


def check_file(target_path: Path, hash_path: Path, cache: dict) -> None:
    """Handles hashes for a single file.

    Takes a target file path, hashes cache path and a cache. Handles hash checking logic
    for a single file using `json` and the `sha256` hashing algorithm.

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

    # find previous crc if available
    crcdict = dict()
    test = str(hash_path)
    crc_path = Path(test[:-11] + '/crc.json') # get crc path from hashes.json

    if not crc_path.is_file():
        with open(crc_path, "w", encoding="utf-8") as file:
            json.dump(dict(), file, indent=4)

    with open(crc_path, "r") as file:
        crcdict = json.load(file)

    # find new crc and compare with previous to see if changed
    buffer = io.BytesIO()
    with SevenZipFile(buffer, "w",) as zip_file:
        if target_path.is_file():
            print("Compressing", target_path)
            zip_file.write(target_path, arcname=target_path.name)

    buffer.seek(0)
    with SevenZipFile(buffer, "r") as zip_file:
        for member in zip_file.list():
            print(member)
            # Using .crc32 and handling cases where a directory might have a None CRC
            crc_value = hex(member.crc32) if member.crc32 is not None else "N/A"
            print(f"File: {member.filename} | CRC32: {crc_value}")

            # check if the crc values have changed
            if member.filename in crcdict:
                if (crc_value != crcdict[member.filename]):
                    print(f"CRC mismatch for {member.filename}")

            # update crc values
            crcdict[member.filename] = crc_value

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
            cache[str(target_path)] = filehash.hexdigest()
            print("The contents or metadata of the file has been verified to have changed from its past scan. Proceed with caution.")

    print("Running the hashcheck tool did not run or execute files and only verified the integrity of the specified file or directory.")

    # Save file
    with open(hash_path, "w", encoding="utf-8") as file:
        json.dump(cache, file, indent=4)

    with open(crc_path, "w", encoding="utf-8") as file:
        json.dump(crcdict, file, indent=4)



def check_dir(target_path: Path, hash_path: Path, cache: dict) -> None:
    """Handles hashes for a directory.

    Takes a target directory path, hashes cache path and a cache. Handles hash checking logic
    for a directory using `json`, `zip`, and the `sha256` hashing algorithm.

    Args:
        target_path (Path): The path to the desired directory to check.
        hash_path (Path): The path to the hash cache.
        cache (dict): A dictionary of previous file/directory hashes.
    
    Returns:
        None.
    """
    buffer = io.BytesIO()
    hasher = hashlib.new("sha256")

    with SevenZipFile(buffer, "w",) as zip_file:
        for file in sorted(target_path.rglob("*")):
            if file.is_file():
                print("Compressing", file)
                zip_file.write(file, arcname=file.relative_to(target_path))


    buffer.seek(0)

    crcdict = dict()
    test = str(hash_path)
    crc_path = Path(test[:-11] + '/crc.json') # get crc path from hashes.json

    if not crc_path.is_file():
        with open(crc_path, "w", encoding="utf-8") as file:
            json.dump(dict(), file, indent=4)

    with open(crc_path, "r") as file:
        crcdict = json.load(file)

    # dummy test
    # crcdict['hello.zip'] = 1

    with SevenZipFile(buffer, "r") as zip_file:
        for member in zip_file.list():
            # Using .crc32 and handling cases where a directory might have a None CRC
            crc_value = hex(member.crc32) if member.crc32 is not None else "N/A"
            print(f"File: {member.filename} | CRC32: {crc_value}")

            # check if the crc values have changed
            if member.filename in crcdict:
                if (crc_value != crcdict[member.filename]):
                    print(f"CRC mismatch for {member.filename}")

            # update crc values
            crcdict[member.filename] = crc_value
            # if member.crc != calculate_crc32(member.data):
            #     print(f"CRC mismatch for {member.filename}")



    buffer.seek(0)
    chunk = buffer.read(8192)
    while chunk:
        hasher.update(chunk)
        chunk = buffer.read(8192)

    dirhash = hasher.hexdigest()
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
    with open(hash_path, "w", encoding="utf-8") as file:
        json.dump(cache, file, indent=4)

    with open(crc_path, "w", encoding="utf-8") as file:
        json.dump(crcdict, file, indent=4)


# ---- Multi-hash and binwalk analysis (new) ---------------------------
MULTI_ALGORITHMS = ("md5", "sha256", "sha512", "blake2b", "blake2s")


def compute_hashes(target_path: Path) -> dict:
    """Computes several hashes of one file in a single read pass.

    Args:
        target_path (Path): The path to the file to hash.

    Returns:
        dict: Maps each algorithm name in `MULTI_ALGORITHMS` to its hex digest.
    """
    hashers = {name: hashlib.new(name) for name in MULTI_ALGORITHMS}
    with open(target_path, "rb") as file:
        chunk = file.read(8192)
        while chunk:
            for hasher in hashers.values():
                hasher.update(chunk)
            chunk = file.read(8192)
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


def record_details(target_path: Path, hash_path: Path, analyze: bool = False) -> None:
    """Stores multi-hash (and optional analysis) data for a file or each file in a directory.

    Writes `cache/multihashes.json` beside the existing `hashes.json`. Each entry holds
    that file's hashes and, if requested, the binwalk output, so the two stay together.

    Args:
        target_path (Path): The user-provided file or directory.
        hash_path (Path): The path to the existing hash cache (used to locate `cache/`).
        analyze (bool): Whether to run `binwalk` on each file.

    Returns:
        None.
    """
    details_path = hash_path.parent / "multihashes.json"
    details = dict()
    if details_path.is_file():
        with open(details_path, "r") as file:
            details = json.load(file)

    if target_path.is_file():
        files = [target_path]
    else:
        files = sorted(f for f in target_path.rglob("*") if f.is_file())

    for file_path in files:
        entry = {"hashes": compute_hashes(file_path)}
        if analyze:
            entry["analysis"] = {"binwalk": run_analysis(file_path)}
        details[str(file_path)] = entry

    with open(details_path, "w", encoding="utf-8") as file:
        json.dump(details, file, indent=4)


# ---- Main ------------------------------------------------------------
if __name__ == "__main__":
    ANALYZE = "--analyze" in sys.argv
    if ANALYZE:
        sys.argv.remove("--analyze")

    if len(sys.argv) == 2:
        TARGET_PATH, HASH_PATH, CACHE = handle_paths(sys.argv[1])

        if TARGET_PATH.is_file():
            check_file(TARGET_PATH, HASH_PATH, CACHE)
            record_details(TARGET_PATH, HASH_PATH, ANALYZE)
        elif TARGET_PATH.is_dir():
            check_dir(TARGET_PATH, HASH_PATH, CACHE)
            record_details(TARGET_PATH, HASH_PATH, ANALYZE)
        else:
            print(f"Illegal Argument: You passed {TARGET_PATH} while only valid files or directories are accepted.\nUsage:\n\tpython3 hashcheck.py <file/directory> [--analyze]")
        
    else:
        print(f"Illegal Argument(s): You passed {len(sys.argv)-1} arguments while only 1 is accepted.\nUsage:\n\tpython3 hashcheck.py <file/directory> [--analyze]")

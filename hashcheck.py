#!/usr/bin/env python3
# python hashcheck.py <file/directory>
# ----------------------------------------------------------------------
# Title    : File Integrity Monitor
# Authors  : Jadon Duff, Jacob Ewasko
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


# ---- Main ------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) == 2:
        TARGET_PATH, HASH_PATH, CACHE = handle_paths(sys.argv[1])

        if TARGET_PATH.is_file():
            check_file(TARGET_PATH, HASH_PATH, CACHE)
        elif TARGET_PATH.is_dir():
            check_dir(TARGET_PATH, HASH_PATH, CACHE)
        else:
            print(f"Illegal Argument: You passed {TARGET_PATH} while only valid files or directories are accepted.\nUsage:\n\tpython3 hashcheck.py <file/directory>")
        
    else:
        print(f"Illegal Argument(s): You passed {len(sys.argv)-1} arguments while only 1 is accepted.\nUsage:\n\tpython3 hashcheck.py <file/directory>")

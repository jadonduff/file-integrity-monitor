#!/usr/bin/env python3
# python hashcheck.py <file/directory>
# ----------------------------------------------------------------------
# Title    : File Integrity Monitor
# Authors  : Jadon Duff
# Created  : 2026-10-23
# Updated  : 2026-10-23
# Class    : CYB3801 Intro to Cybersecurity
# Project  : Final
# Hardware : Verified Apple M5 Pro (64GB Memory)
# Software : Verified Python 3.14.3
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
from pathlib import Path
import hashlib
import pickle
import sys
import os


# ---- Main ------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) == 2:
        path = Path(sys.argv[1]).resolve()

        # Get Pickle of Hashes
        self_dir = Path(__file__).resolve().parent
        sub_dir = self_dir / "cache"
        pickle_path = sub_dir / "hashes.pkl"

        sub_dir.mkdir(parents=True, exist_ok=True)
        if not pickle_path.is_file():
            with open(pickle_path, "wb") as dump:
                print("You have never run hashcheck before. Setting up...")
                pickle.dump(dict(), dump)

        # Load Pickle
        with open(pickle_path, 'rb') as file:
            cached_hashes = pickle.load(file)

        # Handle file hash
        if path.is_file():
            with open(path, "rb") as file:
                filehash = hashlib.file_digest(file, "sha256")
            print(f"File Hash is: {filehash.hexdigest()}")

            if path not in cached_hashes:
                print("File has not been checked before; adding to cache.")
                cached_hashes[path] = filehash.hexdigest()
            else:
                old_hash = cached_hashes[path]
                if old_hash == filehash.hexdigest():
                    print("File has NOT changed.")
                else:
                    print(f"File has changed! Previous hash was: {old_hash}")
                    cached_hashes[path] = filehash.hexdigest()
                    print("The contents or metadata of the file has been verified to have changed from its past scan. Proceed with caution.")

            print("Running the hashcheck tool did not run or execute files and only verified the integrity of the specified file or directory.")

            # Save pickle
            with open(pickle_path, "wb") as dump:
                pickle.dump(cached_hashes, dump)
                print(f"Hashcheck has saved your data to {pickle_path}")

        # Check for invalid path
        else:
            print(f"Illegal Argument: You passed {path} while only valid files or directories are accepted.\nUsage:\n\tpython3 hashcheck.py <file/directory>")

        
    else:
        print(f"Illegal Argument(s): You passed {len(sys.argv)-1} arguments while only 1 is accepted.\nUsage:\n\tpython3 hashcheck.py <file/directory>")

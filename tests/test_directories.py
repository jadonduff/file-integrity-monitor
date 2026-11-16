"""Directory baselines and limitations of hashing a 7z representation."""

import hashlib
import json
import os
import re
import zlib

import pytest


def test_initial_directory_scan(monitor, sample_directory):
    output = monitor.scan(sample_directory)
    assert "Directory has not been checked before; adding to cache." in output
    digest = monitor.cache()[str(sample_directory)]
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert f"Directory Hash is: {digest}" in output


def test_unchanged_directory_with_multiple_different_files(monitor, sample_directory):
    monitor.scan(sample_directory)
    before = monitor.cache()
    assert "Directory has NOT changed." in monitor.scan(sample_directory)
    assert monitor.cache() == before


@pytest.mark.parametrize("change", ["modify", "add", "delete", "nested", "rename"])
def test_directory_changes_update_baseline(monitor, sample_directory, change):
    monitor.scan(sample_directory)
    previous = monitor.cache()[str(sample_directory)]
    first = sample_directory / "first.txt"
    if change == "modify":
        first.write_bytes(b"changed contents")
    elif change == "add":
        (sample_directory / "added.txt").write_bytes(b"new file")
    elif change == "delete":
        first.unlink()
    elif change == "nested":
        (sample_directory / "nested" / "third.txt").write_bytes(b"nested change")
    else:
        first.rename(sample_directory / "renamed.txt")
    output = monitor.scan(sample_directory)
    assert f"Directory has changed! Previous hash was: {previous}" in output
    assert monitor.cache()[str(sample_directory)] != previous
    assert "Directory has NOT changed." in monitor.scan(sample_directory)


def test_empty_directory(monitor):
    path = monitor.work / "empty"
    path.mkdir()
    assert "Directory has not been checked before" in monitor.scan(path)
    assert "Directory has NOT changed." in monitor.scan(path)


def test_empty_subdirectories_are_ignored(monitor, sample_directory):
    monitor.scan(sample_directory)
    before = monitor.cache()
    empty = sample_directory / "new empty directory"
    empty.mkdir()
    assert "Directory has NOT changed." in monitor.scan(sample_directory)
    empty.rmdir()
    assert "Directory has NOT changed." in monitor.scan(sample_directory)
    assert monitor.cache() == before


@pytest.mark.xfail(strict=True, reason="The archive includes files only, so empty subdirectory additions are invisible")
def test_desired_detection_of_empty_subdirectory_addition(monitor, sample_directory):
    monitor.scan(sample_directory)
    (sample_directory / "empty").mkdir()
    assert "Directory has changed!" in monitor.scan(sample_directory)


def test_directory_hash_includes_file_timestamp(monitor, sample_directory):
    path = sample_directory / "first.txt"
    os.utime(path, (1700000000, 1700000000))
    monitor.scan(sample_directory)
    previous = monitor.cache()[str(sample_directory)]
    os.utime(path, (1700000100, 1700000100))
    assert "Directory has changed!" in monitor.scan(sample_directory)
    assert monitor.cache()[str(sample_directory)] != previous


@pytest.mark.skipif(os.name != "posix", reason="Requires symbolic links")
def test_symbolic_link_to_a_file_is_scanned(monitor, sample_directory):
    os.symlink(sample_directory / "first.txt", sample_directory / "link.txt")
    assert "Directory has not been checked before" in monitor.scan(sample_directory)
    assert "Directory has NOT changed." in monitor.scan(sample_directory)


def test_same_directory_scanned_by_relative_and_absolute_path_shares_a_baseline(monitor, sample_directory):
    monitor.scan(sample_directory.name)
    assert "Directory has NOT changed." in monitor.scan(sample_directory)
    assert list(monitor.cache()) == [str(sample_directory)]


def crc(data):
    return hex(zlib.crc32(data))


ALGORITHMS = ("md5", "sha256", "sha512", "blake2b", "blake2s")


def digests(data):
    return {name: hashlib.new(name, data).hexdigest() for name in ALGORITHMS}


def test_directory_scan_stores_crc32_per_file(monitor, sample_directory):
    output = monitor.scan(sample_directory)
    assert f"File: nested/third.txt | CRC32: {crc(b'nested contents')}" in output
    assert monitor.cache("crc.json") == {
        str(path): crc(path.read_bytes()) for path in sample_directory.rglob("*") if path.is_file()
    }


def test_directory_scan_names_the_file_with_a_crc_mismatch(monitor, sample_directory):
    monitor.scan(sample_directory)
    (sample_directory / "nested" / "third.txt").write_bytes(b"nested change")
    output = monitor.scan(sample_directory)
    assert output.count("CRC mismatch") == 1
    assert "CRC mismatch for nested/third.txt" in output


def test_same_file_names_in_two_directories_do_not_collide(monitor, sample_directory):
    other = monitor.work / "other"
    other.mkdir()
    (other / "first.txt").write_bytes(b"not the same contents")
    monitor.scan(sample_directory)
    assert "CRC mismatch" not in monitor.scan(other)
    assert "CRC mismatch" not in monitor.scan(sample_directory)


@pytest.mark.parametrize("scan_first", ["file", "directory"])
def test_file_and_its_directory_share_one_crc_entry(monitor, sample_directory, scan_first):
    path = sample_directory / "first.txt"
    scans = [path, sample_directory] if scan_first == "file" else [sample_directory, path]
    for scan in scans:
        assert "CRC mismatch" not in monitor.scan(scan)


def test_directory_scan_stores_content_of_every_file(monitor, sample_directory):
    monitor.scan(sample_directory)
    stored = monitor.cache("content.json")
    assert set(stored) == {str(path) for path in sample_directory.rglob("*") if path.is_file()}
    assert stored[str(sample_directory / "first.txt")] == "first contents"


def test_directory_scan_prints_a_diff_only_for_the_changed_file(monitor, sample_directory):
    monitor.scan(sample_directory)
    (sample_directory / "first.txt").write_bytes(b"first changed")
    output = monitor.scan(sample_directory)
    assert output.count("File content has changed!") == 1
    assert "File content has changed! File: first.txt" in output
    assert "-first contents\n\\ No newline at end of file\n+first changed\n\\ No newline at end of file\n" in output
    assert monitor.cache("content.json")[str(sample_directory / "first.txt")] == "first changed"
    assert "File content has changed!" not in monitor.scan(sample_directory)


def test_directory_scan_with_an_added_file_prints_no_diff(monitor, sample_directory):
    monitor.scan(sample_directory)
    (sample_directory / "added.txt").write_bytes(b"new file")
    output = monitor.scan(sample_directory)
    assert "Directory has changed!" in output
    assert "File content has changed!" not in output
    assert monitor.cache("content.json")[str(sample_directory / "added.txt")] == "new file"


def test_files_with_the_same_name_in_two_directories_are_not_compared(monitor, sample_directory):
    other = monitor.work / "other"
    other.mkdir()
    (other / "first.txt").write_bytes(b"completely different")
    monitor.scan(sample_directory)
    assert "File content has changed!" not in monitor.scan(other)
    assert "File content has changed!" not in monitor.scan(sample_directory)


def test_directory_baseline_from_an_older_cache_without_content(monitor, sample_directory):
    monitor.cache_path.parent.mkdir()
    monitor.cache_path.write_text(json.dumps({str(sample_directory): "0" * 64}), encoding="utf-8")
    output = monitor.scan(sample_directory)
    assert "Directory has changed!" in output
    assert "File content has changed!" not in output
    assert "Directory has NOT changed." in monitor.scan(sample_directory)


def test_file_and_its_directory_share_one_content_entry(monitor, sample_directory):
    path = sample_directory / "first.txt"
    monitor.scan(path)
    path.write_bytes(b"first changed")
    output = monitor.scan(sample_directory)
    assert "File content has changed! File: first.txt" in output
    assert "-first contents" in output
    assert "+first changed" in output


def test_directory_scan_stores_hashes_for_every_file_but_not_the_directory(monitor, sample_directory):
    monitor.scan(sample_directory)
    stored = monitor.cache("multihashes.json")
    files = [path for path in sample_directory.rglob("*") if path.is_file()]
    assert set(stored) == {str(path) for path in files}
    for path in files:
        assert stored[str(path)] == {"hashes": digests(path.read_bytes())}


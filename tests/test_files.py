"""File contents, names, and baseline updates through the real CLI."""

import hashlib
import os

import pytest


def test_initial_file_scan(monitor, sample_file):
    output = monitor.scan(sample_file)
    expected = hashlib.sha256(sample_file.read_bytes()).hexdigest()
    assert "File has not been checked before; adding to cache." in output
    assert f"File Hash is: {expected}" in output
    assert monitor.cache() == {str(sample_file.resolve()): expected}


@pytest.mark.parametrize("contents", [b"", b"abc", bytes(range(256)) * 64, "Hello 世界 🌍\n".encode()])
def test_sha256_for_empty_text_binary_and_unicode(monitor, sample_file, contents):
    sample_file.write_bytes(contents)
    output = monitor.scan(sample_file)
    expected = hashlib.sha256(contents).hexdigest()
    assert f"File Hash is: {expected}" in output
    assert monitor.cache()[str(sample_file)] == expected


def test_unchanged_file(monitor, sample_file):
    monitor.scan(sample_file)
    before = monitor.cache()
    assert "File has NOT changed." in monitor.scan(sample_file)
    assert monitor.cache() == before


@pytest.mark.parametrize("before,after", [(b"before", b"after!"), (b"", b"added"), (b"removed", b"")])
def test_modified_contents_update_baseline(monitor, sample_file, before, after):
    sample_file.write_bytes(before)
    monitor.scan(sample_file)
    sample_file.write_bytes(after)
    output = monitor.scan(sample_file)
    assert f"File has changed! Previous hash was: {hashlib.sha256(before).hexdigest()}" in output
    assert monitor.cache()[str(sample_file)] == hashlib.sha256(after).hexdigest()
    assert "File has NOT changed." in monitor.scan(sample_file)


@pytest.mark.parametrize("name", ["file with spaces.txt", "résumé 世界.txt"])
def test_special_filenames(monitor, name):
    path = monitor.work / name
    path.write_bytes(b"special name")
    assert "File has not been checked before" in monitor.scan(path)
    assert str(path.resolve()) in monitor.cache()
    assert "File has NOT changed." in monitor.scan(path)


def test_file_timestamp_only_change_is_not_detected(monitor, sample_file):
    monitor.scan(sample_file)
    before = monitor.cache()
    os.utime(sample_file, (1700000000, 1700000000))
    assert "File has NOT changed." in monitor.scan(sample_file)
    assert monitor.cache() == before

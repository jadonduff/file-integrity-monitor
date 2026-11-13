"""Directory baselines and limitations of hashing a ZIP representation."""

import os
import re

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


@pytest.mark.xfail(strict=True, reason="ZIP includes files only, so empty subdirectory additions are invisible")
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

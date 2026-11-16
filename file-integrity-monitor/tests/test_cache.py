"""On-disk persistence and observed malformed-cache behavior."""

import hashlib
import json

import pytest


def test_cache_created_beside_script_not_working_directory(monitor, sample_file):
    assert not monitor.cache_path.parent.exists()
    monitor.scan(sample_file)
    assert monitor.cache_path.is_file()
    assert not (monitor.work / "cache").exists()
    assert monitor.cache() == {str(sample_file): hashlib.sha256(sample_file.read_bytes()).hexdigest()}


def test_cache_persists_between_processes(monitor, sample_file):
    monitor.scan(sample_file)
    saved = monitor.cache_path.read_bytes()
    assert "File has NOT changed." in monitor.scan(sample_file)
    assert monitor.cache_path.read_bytes() == saved


def test_multiple_paths_preserved_when_one_changes(monitor, sample_file, sample_directory):
    other = monitor.work / "other.txt"
    other.write_bytes(b"another file")
    for path in (sample_file, other, sample_directory):
        monitor.scan(path)
    before = monitor.cache()
    assert set(before) == {str(sample_file), str(other), str(sample_directory)}
    sample_file.write_bytes(b"updated")
    monitor.scan(sample_file)
    assert monitor.cache() == {**before, str(sample_file): hashlib.sha256(b"updated").hexdigest()}


@pytest.mark.parametrize("payload,error", [("{broken", "JSONDecodeError"), ("", "JSONDecodeError"), ("[]", "TypeError"), ("null", "TypeError"), ("42", "TypeError")])
def test_malformed_cache_fails_without_overwriting(monitor, sample_file, payload, error):
    monitor.cache_path.parent.mkdir()
    monitor.cache_path.write_text(payload, encoding="utf-8")
    result = monitor.run(sample_file)
    assert result.returncode != 0
    assert error in result.stderr
    assert monitor.cache_path.read_text(encoding="utf-8") == payload


def test_invalid_cached_digest_is_replaced_as_a_change(monitor, sample_file):
    monitor.cache_path.parent.mkdir()
    monitor.cache_path.write_text(json.dumps({str(sample_file): "invalid-digest"}), encoding="utf-8")
    assert "File has changed! Previous hash was: invalid-digest" in monitor.scan(sample_file)
    assert monitor.cache()[str(sample_file)] == hashlib.sha256(sample_file.read_bytes()).hexdigest()


def test_cache_directory_holds_every_cache_file_and_no_leftovers(monitor, sample_file):
    monitor.scan(sample_file)
    assert sorted(path.name for path in monitor.cache_dir.iterdir()) == [
        "content.json", "crc.json", "hashes.json", "multihashes.json",
    ]
    assert not (monitor.work / "cache").exists()


@pytest.mark.parametrize("name,payload", [("crc.json", "{broken"), ("content.json", ""), ("multihashes.json", "{")])
def test_malformed_side_cache_fails_without_changing_hashes(monitor, sample_file, name, payload):
    monitor.scan(sample_file)
    before = monitor.cache_path.read_bytes()
    (monitor.cache_dir / name).write_text(payload, encoding="utf-8")
    sample_file.write_bytes(b"changed")
    result = monitor.run(sample_file)
    assert result.returncode != 0
    assert "JSONDecodeError" in result.stderr
    if name != "multihashes.json":
        # The side caches are read before anything is written
        assert monitor.cache_path.read_bytes() == before


def test_missing_side_caches_are_recreated_without_touching_the_others(monitor, sample_file):
    monitor.scan(sample_file)
    crc = monitor.cache("crc.json")
    (monitor.cache_dir / "content.json").unlink()
    assert "File has NOT changed." in monitor.scan(sample_file)
    assert monitor.cache("crc.json") == crc
    assert monitor.cache("content.json") == {str(sample_file): "original contents\n"}

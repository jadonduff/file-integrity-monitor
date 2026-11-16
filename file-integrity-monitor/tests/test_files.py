"""File contents, names, and baseline updates through the real CLI."""

import hashlib
import json
import os
import zlib

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


def crc(data):
    return hex(zlib.crc32(data))


ALGORITHMS = ("md5", "sha256", "sha512", "blake2b", "blake2s")


def digests(data):
    return {name: hashlib.new(name, data).hexdigest() for name in ALGORITHMS}


def test_file_scan_prints_and_stores_crc32(monitor, sample_file):
    output = monitor.scan(sample_file)
    assert f"File: sample.txt | CRC32: {crc(b'original contents' + bytes([10]))}" in output
    assert monitor.cache("crc.json") == {str(sample_file): crc(sample_file.read_bytes())}


def test_empty_file_crc32(monitor, sample_file):
    sample_file.write_bytes(b"")
    assert "File: sample.txt | CRC32: 0x0" in monitor.scan(sample_file)


def test_unchanged_file_has_no_crc_mismatch(monitor, sample_file):
    monitor.scan(sample_file)
    assert "CRC mismatch" not in monitor.scan(sample_file)


def test_changed_file_reports_crc_mismatch_and_updates_baseline(monitor, sample_file):
    monitor.scan(sample_file)
    sample_file.write_bytes(b"different")
    assert "CRC mismatch for sample.txt" in monitor.scan(sample_file)
    assert monitor.cache("crc.json")[str(sample_file)] == crc(b"different")
    assert "CRC mismatch" not in monitor.scan(sample_file)


def test_same_file_name_in_different_directories_does_not_collide(monitor):
    first, second = monitor.work / "one" / "same.txt", monitor.work / "two" / "same.txt"
    for path, data in ((first, b"first version"), (second, b"second version")):
        path.parent.mkdir()
        path.write_bytes(data)
    assert "CRC mismatch" not in monitor.scan(first)
    assert "CRC mismatch" not in monitor.scan(second)
    assert "CRC mismatch" not in monitor.scan(first)
    assert monitor.cache("crc.json") == {str(first): crc(b"first version"), str(second): crc(b"second version")}


NOT_AVAILABLE = "Not available: no content was stored for one of the two versions."


def test_content_is_stored_by_full_path(monitor, sample_file):
    monitor.scan(sample_file)
    assert monitor.cache("content.json") == {str(sample_file): "original contents\n"}


def test_changed_file_prints_a_unified_diff_and_updates_the_stored_content(monitor, sample_file):
    monitor.scan(sample_file)
    sample_file.write_bytes(b"updated contents\n")
    output = monitor.scan(sample_file)
    assert "Difference since last update:" in output
    assert "--- previous\n+++ current\n" in output
    assert "-original contents\n+updated contents\n" in output
    assert monitor.cache("content.json") == {str(sample_file): "updated contents\n"}
    assert "Difference since last update:" not in monitor.scan(sample_file)


def test_diff_is_printed_between_the_change_message_and_the_warning(monitor, sample_file):
    monitor.scan(sample_file)
    sample_file.write_bytes(b"updated contents\n")
    output = monitor.scan(sample_file)
    assert output.index("File has changed!") < output.index("Difference since last update:") < output.index("Proceed with caution.")


def test_unchanged_file_prints_no_diff(monitor, sample_file):
    monitor.scan(sample_file)
    assert "Difference since last update:" not in monitor.scan(sample_file)


def test_missing_trailing_newline_is_marked(monitor, sample_file):
    monitor.scan(sample_file)
    sample_file.write_bytes(b"original contents")
    assert "+original contents\n\\ No newline at end of file\n" in monitor.scan(sample_file)


def test_line_ending_only_change_is_visible(monitor, sample_file):
    sample_file.write_bytes(b"one\ntwo\n")
    monitor.scan(sample_file)
    sample_file.write_bytes(b"one\r\ntwo\r\n")
    output = monitor.scan(sample_file)
    # The captured output has its line endings normalized, but the diff is not empty
    assert "-one\n-two\n+one\n+two\n" in output
    assert monitor.cache("content.json") == {str(sample_file): "one\r\ntwo\r\n"}


def test_non_text_file_is_stored_as_the_repr_of_its_bytes(monitor, sample_file):
    sample_file.write_bytes(b"\xff\xfe\x00binary")
    monitor.scan(sample_file)
    assert monitor.cache("content.json") == {str(sample_file): repr(b"\xff\xfe\x00binary")}
    sample_file.write_bytes(b"\xff\xfe\x00BINARY")
    output = monitor.scan(sample_file)
    assert "Difference since last update:" in output
    assert repr(b"\xff\xfe\x00BINARY") in output


def test_unicode_text_round_trips(monitor, sample_file):
    sample_file.write_bytes("héllo 世界\n".encode())
    monitor.scan(sample_file)
    assert monitor.cache("content.json")[str(sample_file)] == "héllo 世界\n"
    sample_file.write_bytes("héllo 世界!\n".encode())
    assert "+héllo 世界!" in monitor.scan(sample_file)


def test_baseline_from_an_older_cache_without_content_reports_the_change(monitor, sample_file):
    monitor.cache_path.parent.mkdir()
    monitor.cache_path.write_text(json.dumps({str(sample_file): hashlib.sha256(b"old").hexdigest()}), encoding="utf-8")
    output = monitor.scan(sample_file)
    assert "File has changed!" in output
    assert NOT_AVAILABLE in output
    assert monitor.cache("content.json") == {str(sample_file): "original contents\n"}
    assert "File has NOT changed." in monitor.scan(sample_file)


def test_file_over_the_size_limit_is_not_stored(monitor, sample_file):
    sample_file.write_bytes(b"a" * (1024 * 1024 + 1))
    monitor.scan(sample_file)
    assert monitor.cache("content.json") == {}
    sample_file.write_bytes(b"b" * (1024 * 1024 + 1))
    output = monitor.scan(sample_file)
    assert "File has changed!" in output
    assert NOT_AVAILABLE in output


def test_file_at_the_size_limit_is_stored(monitor, sample_file):
    sample_file.write_bytes(b"a" * (1024 * 1024))
    monitor.scan(sample_file)
    assert monitor.cache("content.json") == {str(sample_file): "a" * (1024 * 1024)}


def test_stored_content_of_a_file_that_grows_past_the_limit_is_dropped(monitor, sample_file):
    monitor.scan(sample_file)
    sample_file.write_bytes(b"a" * (1024 * 1024 + 1))
    monitor.scan(sample_file)
    assert monitor.cache("content.json") == {}
    sample_file.write_bytes(b"small again\n")
    assert NOT_AVAILABLE in monitor.scan(sample_file)


def test_file_scan_stores_every_hash(monitor, sample_file):
    monitor.scan(sample_file)
    assert monitor.cache("multihashes.json") == {str(sample_file): {"hashes": digests(sample_file.read_bytes())}}


def test_hashes_json_format_is_unchanged(monitor, sample_file):
    monitor.scan(sample_file)
    assert monitor.cache() == {str(sample_file): hashlib.sha256(sample_file.read_bytes()).hexdigest()}
    assert monitor.cache("multihashes.json")[str(sample_file)]["hashes"]["sha256"] == monitor.cache()[str(sample_file)]


def test_empty_and_large_files(monitor, sample_file):
    for data in (b"", bytes(range(256)) * 1000):
        sample_file.write_bytes(data)
        monitor.scan(sample_file)
        assert monitor.cache("multihashes.json")[str(sample_file)]["hashes"] == digests(data)


def test_rescan_updates_changed_file_and_keeps_other_entries(monitor, sample_file):
    other = monitor.work / "other.txt"
    other.write_bytes(b"another file")
    monitor.scan(sample_file)
    monitor.scan(other)
    sample_file.write_bytes(b"updated")
    monitor.scan(sample_file)
    assert monitor.cache("multihashes.json") == {
        str(sample_file): {"hashes": digests(b"updated")},
        str(other): {"hashes": digests(b"another file")},
    }


def test_optional_results_are_absent_without_flags(monitor, sample_file):
    monitor.scan(sample_file)
    assert set(monitor.cache("multihashes.json")[str(sample_file)]) == {"hashes"}


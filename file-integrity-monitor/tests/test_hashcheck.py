"""Direct tests of the application's functions, and the optional --analyze and --detect-encryption flags."""

import hashlib
import json
import stat
import subprocess
from types import SimpleNamespace

import pytest

# First 100 bits of the sequence used in the NIST SP 800-22 worked examples
EPSILON = "1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000"


def bits(text):
    return [int(char) for char in text]


def runs(sequence):
    return 1 + sum(a != b for a, b in zip(sequence, sequence[1:]))


def excursion(sequence):
    total = best = 0
    for bit in sequence:
        total += 1 if bit else -1
        best = max(best, abs(total))
    return best


def to_bits(data):
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


# ---- Statistics ------------------------------------------------------
@pytest.mark.parametrize("a,x,expected", [
    (0.5, 0.1, 0.6547208460185768),
    (3.5, 1.0, 0.9598403687301016),
    (3.5, 10.0, 0.005569683072945574),
    (32.0, 50.0, 0.0026862828946550184),
    (127.5, 100.0, 0.9954254445419519),
    (127.5, 127.5, 0.48822252177040637),
    (127.5, 200.0, 1.6600025244123397e-08),
    (127.5, 400.0, 1.5154857610289696e-57),
])
def test_incomplete_gamma_matches_reference_values(hashcheck, a, x, expected):
    assert hashcheck._igamc(a, x) == pytest.approx(expected, rel=1e-9)


def test_incomplete_gamma_at_zero_is_one(hashcheck):
    assert hashcheck._igamc(3.0, 0.0) == 1.0


def test_normal_cdf(hashcheck):
    assert hashcheck._normal_cdf(0.0) == 0.5
    assert hashcheck._normal_cdf(1.959964) == pytest.approx(0.975, abs=1e-6)


def test_nist_frequency_examples(hashcheck):
    assert hashcheck._monobit_p(sum(bits("1011010101")), 10) == pytest.approx(0.527089, abs=1e-6)
    assert hashcheck._monobit_p(sum(bits(EPSILON)), 100) == pytest.approx(0.109599, abs=1e-6)


def test_nist_block_frequency_examples(hashcheck):
    assert hashcheck._block_frequency_p([2, 1, 2], 3) == pytest.approx(0.801252, abs=1e-6)
    sequence = bits(EPSILON)
    assert hashcheck._block_frequency_p([sum(sequence[i:i + 10]) for i in range(0, 100, 10)], 10) == pytest.approx(0.706438, abs=1e-6)


def test_nist_runs_examples(hashcheck):
    sequence = bits("1001101011")
    assert hashcheck._runs_p(sum(sequence), runs(sequence), 10) == pytest.approx(0.147232, abs=1e-6)
    sequence = bits(EPSILON)
    assert hashcheck._runs_p(sum(sequence), runs(sequence), 100) == pytest.approx(0.500798, abs=1e-6)


def test_runs_frequency_pretest_failure_gives_zero(hashcheck):
    assert hashcheck._runs_p(90, 20, 100) == 0.0


def test_nist_cumulative_sums_example(hashcheck):
    sequence = bits(EPSILON)
    assert hashcheck._cusum_p(excursion(sequence), 100) == pytest.approx(0.219194, abs=1e-6)
    assert hashcheck._cusum_p(excursion(sequence[::-1]), 100) == pytest.approx(0.114866, abs=1e-6)


@pytest.mark.parametrize("size", [1280, 1500, 4096])
def test_byte_level_tests_match_a_bit_level_reference(hashcheck, random_bytes, size):
    block = random_bytes(size, seed=b"reference")
    sequence = to_bits(block)
    n = len(sequence)
    chunk = hashcheck.DETECT_FREQ_CHUNK * 8
    expected = {
        "frequency": hashcheck._monobit_p(sum(sequence), n),
        "block_frequency": hashcheck._block_frequency_p(
            [sum(sequence[i:i + chunk]) for i in range(0, n - chunk + 1, chunk)], chunk
        ),
        "runs": hashcheck._runs_p(sum(sequence), runs(sequence), n),
        "cumulative_sums": min(
            hashcheck._cusum_p(excursion(sequence), n), hashcheck._cusum_p(excursion(sequence[::-1]), n)
        ),
    }
    assert hashcheck.nist_tests(block) == pytest.approx(expected, rel=1e-12, abs=1e-15)


def test_walk_tables_match_a_bit_level_reference(hashcheck, random_bytes):
    data = random_bytes(500, seed=b"walk")
    assert hashcheck._max_excursion(data, hashcheck._WALK_FORWARD) == excursion(to_bits(data))
    assert hashcheck._max_excursion(data[::-1], hashcheck._WALK_BACKWARD) == excursion(to_bits(data)[::-1])


def test_chi_square_of_perfectly_uniform_bytes(hashcheck):
    result = hashcheck.chi_square_bytes(bytes(range(256)) * 20)
    assert result["chi_square"] == 0.0
    assert result["chi_square_p"] == 1.0
    assert result["mean_byte"] == 127.5
    assert result["mean_byte_p"] == 1.0


def test_chi_square_of_a_single_repeated_byte(hashcheck):
    result = hashcheck.chi_square_bytes(bytes(2560))
    assert result["chi_square"] == pytest.approx(652800)
    assert result["chi_square_p"] < 1e-300
    assert result["mean_byte_p"] < 1e-300


def test_chi_square_p_matches_the_statistic(hashcheck, random_bytes):
    data = random_bytes(4096)
    result = hashcheck.chi_square_bytes(data)
    assert result["chi_square_p"] == pytest.approx(hashcheck._igamc(127.5, result["chi_square"] / 2))
    assert 0.001 < result["chi_square_p"] < 0.999


def test_random_like_check(hashcheck, random_bytes):
    assert hashcheck.is_random_like(random_bytes(4096)) is True
    assert hashcheck.is_random_like(b"The quick brown fox jumps over the lazy dog. " * 100) is False
    # Too uniform is as suspicious as too lumpy
    assert hashcheck.is_random_like(bytes(range(256)) * 16) is False
    assert hashcheck.is_random_like(bytes(4096)) is False


@pytest.mark.parametrize("flags,expected", [
    ([1] * 20 + [0] * 20, [20]),
    ([0] * 12 + [1] * 12 + [0] * 12, [12, 24]),
    ([1] * 40, []),
    ([0] * 40, []),
    ([1] * 30 + [0] + [1] * 30, []),
    ([1] * 7, []),
    ([], []),
])
def test_change_points(hashcheck, flags, expected):
    assert hashcheck.find_change_points(flags) == expected


def test_change_points_need_both_sides_to_be_long_enough(hashcheck):
    assert hashcheck.find_change_points([1] * 20 + [0] * 3) == []


# ---- Signatures ------------------------------------------------------
def test_encrypted_signatures_must_start_within_their_offset(hashcheck, tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"")
    assert hashcheck.detect_signatures(b"Salted__", path)[0] == ["OpenSSL enc output"]
    assert hashcheck.detect_signatures(b"x" + b"Salted__", path)[0] == []
    assert hashcheck.detect_signatures(b" " * 256 + b"-----BEGIN PGP MESSAGE-----", path)[0] == ["OpenPGP/GPG armored message"]
    assert hashcheck.detect_signatures(b" " * 257 + b"-----BEGIN PGP MESSAGE-----", path)[0] == []


@pytest.mark.parametrize("head,name", [
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh9", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip (its contents may still be encrypted)"),
    (b"PK\x03\x04\x14\x00\x00\x00", "ZIP"),
    (b"Rar!\x1a\x07\x00", "RAR"),
    (b"(\xb5/\xfd", "Zstandard"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff\xe0", "JPEG"),
])
def test_compressed_signatures(hashcheck, tmp_path, head, name):
    path = tmp_path / "file"
    path.write_bytes(b"")
    assert hashcheck.detect_signatures(head, path) == ([], [name])


def test_short_zip_header_does_not_crash(hashcheck, tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"")
    assert hashcheck.detect_signatures(b"PK\x03\x04", path) == ([], ["ZIP"])


def test_ntfs_encrypted_attribute(hashcheck):
    class FakePath:
        def stat(self):
            return SimpleNamespace(st_file_attributes=stat.FILE_ATTRIBUTE_ENCRYPTED | stat.FILE_ATTRIBUTE_ARCHIVE)

    assert hashcheck.detect_signatures(b"", FakePath())[0] == ["NTFS EFS encrypted file attribute"]


def test_only_the_first_bytes_are_analyzed(hashcheck, tmp_path, random_bytes, monkeypatch):
    path = tmp_path / "file"
    path.write_bytes(random_bytes(20000))
    monkeypatch.setattr(hashcheck, "DETECT_MAX_BYTES", 8192)
    result = hashcheck.detect_encryption(path)
    assert (result["size_bytes"], result["bytes_analyzed"], result["statistics"]["blocks"]) == (20000, 8192, 2)


def test_trailing_partial_block_is_skipped(hashcheck, tmp_path, random_bytes):
    path = tmp_path / "file"
    path.write_bytes(random_bytes(4096 * 3 + 2000))
    result = hashcheck.detect_encryption(path)
    assert result["statistics"]["blocks"] == 3
    assert result["regions"][-1]["end_byte"] == 4096 * 3


# ---- Helpers ---------------------------------------------------------
def test_save_json_replaces_the_file_and_leaves_no_temporary_file(hashcheck, tmp_path):
    path = tmp_path / "cache.json"
    hashcheck.save_json(path, {"a": 1})
    hashcheck.save_json(path, {"b": "世界"})
    assert json.loads(path.read_text(encoding="utf-8")) == {"b": "世界"}
    assert [item.name for item in tmp_path.iterdir()] == ["cache.json"]


def test_failed_save_keeps_the_previous_file(hashcheck, tmp_path):
    path = tmp_path / "cache.json"
    hashcheck.save_json(path, {"a": 1})
    with pytest.raises(TypeError):
        hashcheck.save_json(path, {"a": object()})
    assert json.loads(path.read_text(encoding="utf-8")) == {"a": 1}
    assert [item.name for item in tmp_path.iterdir()] == ["cache.json"]


def test_load_json_creates_a_missing_file(hashcheck, tmp_path):
    path = tmp_path / "new.json"
    assert hashcheck.load_json(path) == {}
    assert json.loads(path.read_text(encoding="utf-8")) == {}


def test_read_content(hashcheck, tmp_path, monkeypatch):
    path = tmp_path / "file"
    path.write_bytes("héllo\r\n".encode())
    assert hashcheck.read_content(path) == "héllo\r\n"
    path.write_bytes(b"\xff\xfe")
    assert hashcheck.read_content(path) == repr(b"\xff\xfe")
    monkeypatch.setattr(hashcheck, "CONTENT_MAX_BYTES", 4)
    path.write_bytes(b"1234")
    assert hashcheck.read_content(path) == "1234"
    path.write_bytes(b"12345")
    assert hashcheck.read_content(path) is None


def test_store_content(hashcheck):
    stored = {}
    hashcheck.store_content(stored, "a", "text")
    assert stored == {"a": "text"}
    hashcheck.store_content(stored, "a", None)
    hashcheck.store_content(stored, "missing", None)
    assert stored == {}


def test_print_diff(hashcheck, capsys):
    hashcheck.print_diff("one\ntwo\n", "one\n2\n")
    assert capsys.readouterr().out == (
        "Difference since last update:\n--- previous\n+++ current\n@@ -1,2 +1,2 @@\n one\n-two\n+2\n"
    )


def test_print_diff_marks_a_missing_final_newline(hashcheck, capsys):
    hashcheck.print_diff("same\nlast", "same\nlast\n")
    assert capsys.readouterr().out.endswith(" same\n-last\n\\ No newline at end of file\n+last\n")


def test_print_diff_treats_only_newlines_as_line_breaks(hashcheck, capsys):
    hashcheck.print_diff("a\u2028b\x0bc\n", "a\u2028b\x0bd\n")
    out = capsys.readouterr().out
    assert out.count("-a\u2028b\x0bc\n") == 1 and out.count("+a\u2028b\x0bd\n") == 1


@pytest.mark.parametrize("old,new", [(None, "x"), ("x", None), (None, None)])
def test_print_diff_without_both_versions(hashcheck, capsys, old, new):
    hashcheck.print_diff(old, new)
    assert capsys.readouterr().out == (
        "Difference since last update:\nNot available: no content was stored for one of the two versions.\n"
    )


def test_compute_hashes(hashcheck, tmp_path):
    path = tmp_path / "file"
    data = bytes(range(256)) * 1000 + b"tail"
    path.write_bytes(data)
    assert hashcheck.compute_hashes(path) == {name: hashlib.new(name, data).hexdigest() for name in hashcheck.MULTI_ALGORITHMS}


def test_compress_names_members_and_reads_back_crcs(hashcheck, tmp_path, capsys):
    (tmp_path / "a.txt").write_bytes(b"hello")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_bytes(b"world")
    buffer = hashcheck.compress([(tmp_path / "a.txt", "a.txt"), (tmp_path / "sub" / "b.txt", "sub/b.txt")])
    crcs, seen = {}, []
    hashcheck.review_crcs(buffer, tmp_path, crcs, lambda key, name: seen.append((key, name)))
    assert seen == [(str(tmp_path / "a.txt"), "a.txt"), (str(tmp_path / "sub" / "b.txt"), "sub/b.txt")]
    assert crcs == {str(tmp_path / "a.txt"): hex(0x3610a686), str(tmp_path / "sub" / "b.txt"): hex(0x3a771143)}
    out = capsys.readouterr().out
    assert "File: sub/b.txt | CRC32: 0x3a771143" in out and "CRC mismatch" not in out


# ---- Analysis --------------------------------------------------------
def test_analysis_when_binwalk_is_missing(hashcheck, tmp_path, monkeypatch):
    monkeypatch.setattr(hashcheck.shutil, "which", lambda name: None)
    assert hashcheck.run_analysis(tmp_path / "file") == {"status": "binwalk not installed"}


def test_analysis_when_binwalk_cannot_start(hashcheck, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("boom")

    monkeypatch.setattr(hashcheck.shutil, "which", lambda name: "/usr/bin/binwalk")
    monkeypatch.setattr(hashcheck.subprocess, "run", fail)
    assert hashcheck.run_analysis(tmp_path / "file") == {"status": "failed to run: boom"}


def test_analysis_command_and_exit_status(hashcheck, tmp_path, monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 2, stdout="out", stderr="err")

    monkeypatch.setattr(hashcheck.shutil, "which", lambda name: "/usr/bin/binwalk")
    monkeypatch.setattr(hashcheck.subprocess, "run", fake_run)
    result = hashcheck.run_analysis(tmp_path / "file")
    assert result == {"status": "exit code 2", "output": "out", "stderr": "err"}
    assert calls == [(["binwalk", "-E", "-N", str(tmp_path / "file")], {"capture_output": True, "text": True})]


# ---- Command line: --analyze ------------------------------------------
def analysis(monitor, path):
    return monitor.cache("multihashes.json")[str(path)]["analysis"]["binwalk"]


def test_missing_binwalk_is_recorded_without_failing(monitor, sample_file, tmp_path):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monitor.scan(sample_file, "--analyze", env={"PATH": str(empty)})
    assert analysis(monitor, sample_file) == {"status": "binwalk not installed"}


def test_binwalk_runs_with_entropy_flags_and_output_is_stored(monitor, sample_file, fake_binwalk):
    env = fake_binwalk('echo "entropy report for $@"\necho "a warning" >&2\n')
    monitor.scan(sample_file, "--analyze", env=env)
    assert analysis(monitor, sample_file) == {
        "status": "ok",
        "output": f"entropy report for -E -N {sample_file}\n",
        "stderr": "a warning\n",
    }


def test_binwalk_failure_is_recorded(monitor, sample_file, fake_binwalk):
    env = fake_binwalk('echo "bad flag" >&2\nexit 3\n')
    monitor.scan(sample_file, "--analyze", env=env)
    result = analysis(monitor, sample_file)
    assert result["status"] == "exit code 3"
    assert result["stderr"] == "bad flag\n"


def test_unrunnable_binwalk_is_recorded(monitor, sample_file, fake_binwalk):
    env = fake_binwalk("")
    (monitor.root / "fake-bin" / "binwalk").write_text("not a script", encoding="utf-8")
    monitor.scan(sample_file, "--analyze", env=env)
    assert analysis(monitor, sample_file)["status"].startswith("failed to run:")


def test_directory_scan_analyzes_every_file(monitor, sample_directory, fake_binwalk):
    env = fake_binwalk('echo "$3"\n')
    monitor.scan(sample_directory, "--analyze", env=env)
    stored = monitor.cache("multihashes.json")
    files = [path for path in sample_directory.rglob("*") if path.is_file()]
    assert set(stored) == {str(path) for path in files}
    for path in files:
        assert stored[str(path)]["analysis"]["binwalk"] == {"status": "ok", "output": f"{path}\n", "stderr": ""}


def test_analysis_is_not_run_without_the_flag(monitor, sample_file, fake_binwalk):
    env = fake_binwalk('echo "should not run"\n')
    monitor.scan(sample_file, env=env)
    assert "analysis" not in monitor.cache("multihashes.json")[str(sample_file)]


def test_analysis_leaves_the_other_caches_alone(monitor, sample_file, fake_binwalk):
    env = fake_binwalk("echo ok\n")
    monitor.scan(sample_file)
    before = {name: monitor.cache(name) for name in ("hashes.json", "crc.json", "content.json")}
    monitor.scan(sample_file, "--analyze", env=env)
    assert {name: monitor.cache(name) for name in before} == before


# ---- Command line: --detect-encryption --------------------------------
TEXT = b"The quick brown fox jumps over the lazy dog. " * 2000


def detection(monitor, path):
    return monitor.cache("multihashes.json")[str(path)]["encryption"]


def scan(monitor, path):
    output = monitor.scan(path, "--detect-encryption")
    return detection(monitor, path), output


def test_random_data_is_likely_encrypted(monitor, sample_file, random_bytes):
    sample_file.write_bytes(random_bytes(131072))
    result, output = scan(monitor, sample_file)
    assert result["verdict"].startswith("likely encrypted")
    assert result["statistics"]["random_like_fraction"] >= 0.95
    assert result["compressibility"]["incompressible"] is True
    assert result["regions"] == [{"start_byte": 0, "end_byte": 131072, "random_like": True}]
    assert f"Encryption detection for {sample_file}: {result['verdict']}" in output


def test_text_is_not_flagged(monitor, sample_file):
    sample_file.write_bytes(TEXT[:65536])
    result, _ = scan(monitor, sample_file)
    assert result["verdict"] == "no sign of encryption (structured or compressed data)"
    assert result["statistics"]["random_like_blocks"] == 0
    assert result["compressibility"]["incompressible"] is False
    assert result["regions"] == [{"start_byte": 0, "end_byte": 65536, "random_like": False}]


def test_change_points_locate_the_encrypted_region(monitor, sample_file, random_bytes):
    sample_file.write_bytes(TEXT[:65536] + random_bytes(65536) + TEXT[:65536])
    result, _ = scan(monitor, sample_file)
    assert result["verdict"].startswith("mixed")
    assert result["regions"] == [
        {"start_byte": 0, "end_byte": 65536, "random_like": False},
        {"start_byte": 65536, "end_byte": 131072, "random_like": True},
        {"start_byte": 131072, "end_byte": 196608, "random_like": False},
    ]


@pytest.mark.parametrize("head,name", [
    (b"-----BEGIN PGP MESSAGE-----\n\nhQEMA\n", "OpenPGP/GPG armored message"),
    (b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF\n", "PKCS#8 encrypted private key (PEM)"),
    (b"Salted__", "OpenSSL enc output"),
    (b"LUKS\xba\xbe", "LUKS encrypted volume"),
    (bytes.fromhex("3082010006092a864886f70d010703"), "PKCS#7/CMS envelopedData (DER)"),
    (bytes.fromhex("3082010006092a864886f70d010706"), "PKCS#7/CMS encryptedData (DER)"),
    (b"PK\x03\x04\x14\x00\x01\x00", "ZIP entry with encryption flag set"),
])
def test_encrypted_format_signatures(monitor, sample_file, head, name):
    sample_file.write_bytes(head + bytes(range(256)) * 20)
    result, _ = scan(monitor, sample_file)
    assert name in result["signatures"]["encrypted"]
    assert result["verdict"] == f"encrypted (known signature: {name})"


def test_signature_wins_even_for_a_tiny_file(monitor, sample_file):
    sample_file.write_bytes(b"Salted__12345678")
    result, _ = scan(monitor, sample_file)
    assert result["verdict"].startswith("encrypted (known signature")
    assert result["statistics"] is None


def test_zip_without_the_encryption_flag_is_not_an_encrypted_signature(monitor, sample_file, random_bytes):
    sample_file.write_bytes(b"PK\x03\x04\x14\x00\x00\x00" + random_bytes(65536))
    result, _ = scan(monitor, sample_file)
    assert result["signatures"] == {"encrypted": [], "compressed": ["ZIP"]}
    assert result["verdict"].startswith("random-like data, but a compressed-format signature is present")


def test_random_data_behind_a_compressed_signature_is_likely_compressed(monitor, sample_file, random_bytes):
    sample_file.write_bytes(b"\x1f\x8b" + random_bytes(65536))
    result, _ = scan(monitor, sample_file)
    assert result["verdict"] == "random-like data, but a compressed-format signature is present: likely compressed (gzip)"


@pytest.mark.parametrize("size", [0, 11, 1279])
def test_tiny_files_are_inconclusive(monitor, sample_file, size):
    sample_file.write_bytes(bytes(range(256))[:size] if size < 256 else b"x" * size)
    result, _ = scan(monitor, sample_file)
    assert result["verdict"] == "inconclusive (file too small for statistical tests)"
    assert result["statistics"] is None
    assert result["compressibility"] is None
    assert result["regions"] == []


def test_file_of_exactly_the_minimum_size_is_tested(monitor, sample_file, random_bytes):
    sample_file.write_bytes(random_bytes(1280))
    result, _ = scan(monitor, sample_file)
    assert result["statistics"]["blocks"] == 1
    assert result["verdict"].startswith("likely encrypted")


@pytest.mark.parametrize("size,sixteen,eight", [(4096, True, True), (4104, False, True), (4097, False, False)])
def test_block_alignment(monitor, sample_file, random_bytes, size, sixteen, eight):
    sample_file.write_bytes(random_bytes(size))
    result, _ = scan(monitor, sample_file)
    assert result["block_alignment"] == {"multiple_of_16": sixteen, "multiple_of_8": eight}
    assert result["size_bytes"] == result["bytes_analyzed"] == size


def test_perfectly_uniform_bytes_are_not_random_like(monitor, sample_file):
    sample_file.write_bytes(bytes(range(256)) * 64)
    result, _ = scan(monitor, sample_file)
    assert result["statistics"]["random_like_blocks"] == 0
    assert result["verdict"] == "no sign of encryption (structured or compressed data)"


def test_directory_scan_detects_every_file(monitor, sample_directory, random_bytes):
    (sample_directory / "secret.bin").write_bytes(b"Salted__" + random_bytes(2000))
    output = monitor.scan(sample_directory, "--detect-encryption")
    stored = monitor.cache("multihashes.json")
    files = [path for path in sample_directory.rglob("*") if path.is_file()]
    assert set(stored) == {str(path) for path in files}
    for path in files:
        assert f"Encryption detection for {path}: {stored[str(path)]['encryption']['verdict']}" in output
    assert stored[str(sample_directory / "secret.bin")]["encryption"]["verdict"].startswith("encrypted (known signature")
    assert stored[str(sample_directory / "first.txt")]["encryption"]["verdict"].startswith("inconclusive")


def test_detection_is_not_run_without_the_flag(monitor, sample_file):
    assert "Encryption detection" not in monitor.scan(sample_file)
    assert "encryption" not in monitor.cache("multihashes.json")[str(sample_file)]


def test_both_flags_store_hashes_analysis_and_detection(monitor, sample_file, random_bytes, fake_binwalk):
    sample_file.write_bytes(random_bytes(8192))
    env = fake_binwalk("echo entropy\n")
    monitor.scan(sample_file, "--analyze", "--detect-encryption", env=env)
    assert set(monitor.cache("multihashes.json")[str(sample_file)]) == {"hashes", "analysis", "encryption"}


def test_detection_results_do_not_change_the_integrity_baseline(monitor, sample_file):
    monitor.scan(sample_file)
    before = {name: monitor.cache(name) for name in ("hashes.json", "crc.json", "content.json")}
    assert "File has NOT changed." in monitor.scan(sample_file, "--detect-encryption")
    assert {name: monitor.cache(name) for name in before} == before

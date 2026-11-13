"""CLI validation, including observed successful exits on invalid input."""

import os

import pytest


@pytest.mark.parametrize("args", [(), ("one", "two")])
def test_wrong_argument_count_prints_usage_but_returns_zero(monitor, args):
    result = monitor.run(*args)
    assert result.returncode == 0
    assert f"You passed {len(args)} arguments while only 1 is accepted." in result.stdout
    assert "Usage:" in result.stdout
    assert result.stderr == ""
    assert not monitor.cache_path.exists()


def test_nonexistent_path_prints_usage_and_creates_empty_cache(monitor):
    result = monitor.run(monitor.work / "missing")
    assert result.returncode == 0
    assert "Illegal Argument:" in result.stdout
    assert "Usage:" in result.stdout
    assert result.stderr == ""
    assert monitor.cache() == {}


@pytest.mark.parametrize("args", [(), ("one", "two"), ("missing",)])
@pytest.mark.xfail(strict=True, reason="Invalid CLI inputs print usage but return exit status 0")
def test_desired_invalid_arguments_return_nonzero(monitor, args):
    assert monitor.run(*args).returncode != 0


def test_valid_relative_file_path(monitor, sample_file):
    assert "File has not been checked before" in monitor.scan(sample_file.name)
    assert str(sample_file.resolve()) in monitor.cache()


def test_valid_relative_directory_path(monitor, sample_directory):
    assert "Directory has not been checked before" in monitor.scan(sample_directory.name)
    assert str(sample_directory.resolve()) in monitor.cache()


def test_unreadable_file_reports_permission_error(monitor, sample_file):
    if os.name != "posix":
        pytest.skip("Requires POSIX file permissions")
    original_mode = sample_file.stat().st_mode
    try:
        sample_file.chmod(0)
        try:
            with sample_file.open("rb"):
                pass
        except PermissionError:
            pass
        else:
            pytest.skip("Current user can read mode-000 files (for example container root)")
        result = monitor.run(sample_file)
        assert result.returncode != 0
        assert "PermissionError" in result.stderr
        assert monitor.cache() == {}
    finally:
        sample_file.chmod(original_mode)

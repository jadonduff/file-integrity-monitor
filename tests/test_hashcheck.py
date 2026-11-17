"""Path setup and safe scanning behavior for hashcheck.py."""

import importlib.util
import json

import pytest

@pytest.fixture
def hashcheck_module(monitor):
    """Load the isolated script so helper calls cannot touch the real cache."""
    spec = importlib.util.spec_from_file_location("isolated_hashcheck", monitor.script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_import_does_not_create_cache(hashcheck_module, monitor):
    assert not monitor.cache_path.exists()


def test_handle_paths_resolves_relative_path(hashcheck_module, monitor, sample_file, monkeypatch):
    monkeypatch.chdir(monitor.work)

    target, cache_path, cache = hashcheck_module.handle_paths(sample_file.name)

    assert target == sample_file.resolve()
    assert cache_path == monitor.cache_path
    assert cache == {}
    assert json.loads(cache_path.read_text(encoding="utf-8")) == {}


def test_handle_paths_preserves_existing_cache(hashcheck_module, monitor, sample_file):
    monitor.cache_path.parent.mkdir()
    saved = {str(sample_file.resolve()): "a" * 64}
    original = json.dumps(saved, indent=4)
    monitor.cache_path.write_text(original, encoding="utf-8")

    target, cache_path, cache = hashcheck_module.handle_paths(str(sample_file))

    assert target == sample_file.resolve()
    assert cache_path == monitor.cache_path
    assert cache == saved
    assert cache_path.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("scan_directory", [False, True], ids=["file", "directory"])
def test_scanning_does_not_execute_or_modify_target(monitor, scan_directory):
    target_dir = monitor.work / "scripts"
    target_dir.mkdir()
    marker = monitor.work / "executed.txt"
    script = target_dir / "example.py"
    contents = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
        "raise RuntimeError('The scanned script must not execute')\n"
    ).encode("utf-8")
    script.write_bytes(contents)
    target = target_dir if scan_directory else script
    kind = "Directory" if scan_directory else "File"

    assert f"{kind} has not been checked before" in monitor.scan(target)
    assert f"{kind} has NOT changed." in monitor.scan(target)
    assert not marker.exists()
    assert script.read_bytes() == contents
    assert set(target_dir.iterdir()) == {script}

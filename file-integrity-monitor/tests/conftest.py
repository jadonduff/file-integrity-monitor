"""Isolated CLI fixtures: production code and cache are never executed in place."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


class Monitor:
    def __init__(self, root):
        self.root = root
        self.script = root / "app" / "hashcheck.py"
        self.script.parent.mkdir()
        shutil.copyfile(ROOT / "hashcheck.py", self.script)
        self.cache_dir = self.script.parent / "cache"
        self.cache_path = self.cache_dir / "hashes.json"
        self.work = root / "work"
        self.work.mkdir()

    def run(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(self.script), *(str(arg) for arg in args)],
            cwd=self.work,
            env={**os.environ, "PYTHONIOENCODING": "utf-8", **(env or {})},
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=20,
            check=False,
        )

    def scan(self, path, *flags, env=None):
        result = self.run(path, *flags, env=env)
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stderr == ""
        return result.stdout

    def cache(self, name="hashes.json"):
        return json.loads((self.cache_dir / name).read_text(encoding="utf-8"))


@pytest.fixture
def monitor(tmp_path):
    return Monitor(tmp_path)


@pytest.fixture
def sample_file(monitor):
    path = monitor.work / "sample.txt"
    path.write_bytes(b"original contents\n")
    return path


@pytest.fixture
def sample_directory(monitor):
    path = monitor.work / "directory"
    path.mkdir()
    (path / "first.txt").write_bytes(b"first contents")
    (path / "second.bin").write_bytes(bytes(range(256)))
    nested = path / "nested"
    nested.mkdir()
    (nested / "third.txt").write_bytes(b"nested contents")
    return path


@pytest.fixture(scope="session")
def hashcheck():
    """The application module, for testing its functions directly."""
    spec = importlib.util.spec_from_file_location("hashcheck", ROOT / "hashcheck.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def random_bytes():
    """Deterministic random-looking bytes (SHA-256 in counter mode), so results never flake."""

    def make(size, seed=b"hashcheck"):
        blocks = (size + 31) // 32
        return b"".join(hashlib.sha256(seed + i.to_bytes(8, "big")).digest() for i in range(blocks))[:size]

    return make


@pytest.fixture
def fake_binwalk(tmp_path):
    """Creates a directory holding a fake `binwalk`; returns a function making an env that uses it."""
    if os.name != "posix":
        pytest.skip("Requires a POSIX shell script")
    directory = tmp_path / "fake-bin"
    directory.mkdir()

    def make(script_body):
        path = directory / "binwalk"
        path.write_text("#!/bin/sh\n" + script_body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        return {"PATH": str(directory)}

    return make

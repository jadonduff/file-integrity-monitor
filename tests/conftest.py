"""Isolated CLI fixtures: production code and cache are never executed in place."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


class Monitor:
    def __init__(self, root):
        self.root = root
        self.script = root / "app" / "hashcheck.py"
        self.script.parent.mkdir()
        shutil.copyfile(Path(__file__).resolve().parents[1] / "hashcheck.py", self.script)
        self.cache_path = self.script.parent / "cache" / "hashes.json"
        self.work = root / "work"
        self.work.mkdir()

    def run(self, *args):
        return subprocess.run(
            [sys.executable, str(self.script), *(str(arg) for arg in args)],
            cwd=self.work,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=20,
            check=False,
        )

    def scan(self, path):
        result = self.run(path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stderr == ""
        return result.stdout

    def cache(self):
        return json.loads(self.cache_path.read_text(encoding="utf-8"))


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

"""Exercise reporting independently of application tests in a temporary suite."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest


@pytest.mark.parametrize("fails", [False, True])
def test_runner_reports_results_and_preserves_exit_code(tmp_path, fails):
    suite = tmp_path / "isolated" / "tests"
    suite.mkdir(parents=True)
    runner = suite / "run_suite.py"
    shutil.copyfile(Path(__file__).with_name("run_suite.py"), runner)
    (suite / "test_example.py").write_text(
        "import pytest\n"
        f"def test_outcome():\n    assert {not fails}\n"
        "@pytest.mark.skip(reason='example skip')\n"
        "def test_skip():\n    pass\n"
        "@pytest.mark.xfail(strict=True, reason='example xfail')\n"
        "def test_xfail():\n    assert False\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    # The small probe suite must not inherit options targeting the outer suite.
    env.pop("PYTEST_ADDOPTS", None)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    result = subprocess.run(
        [sys.executable, str(runner)], cwd=tmp_path, env=env,
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert result.returncode == int(fails), result.stdout + result.stderr
    results = suite / "results"
    output = (results / "pytest-output.txt").read_text(encoding="utf-8")
    assert "test_outcome" in output
    assert output in result.stdout
    summary = (results / "summary.txt").read_text(encoding="utf-8")
    assert f"Pytest exit code: {int(fails)}" in summary
    assert f"Passed: {int(not fails)}" in summary
    assert f"Failed: {int(fails)}" in summary
    assert "Skipped: 1" in summary
    assert "Xfailed: 1" in summary
    assert len(list(ET.parse(results / "junit.xml").iter("testcase"))) == 3
    assert not (tmp_path / "results").exists()

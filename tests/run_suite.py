"""Run from any working directory: python /path/to/tests/run_suite.py."""

from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


def main():
    tests_dir = Path(__file__).resolve().parent
    results = tests_dir / "results"
    results.mkdir(parents=True, exist_ok=True)
    junit = results / "junit.xml"
    # Replace the previous XML so an interrupted run cannot summarize stale results.
    junit.unlink(missing_ok=True)
    command = [
        sys.executable, "-m", "pytest", str(tests_dir), "-v", "-ra",
        "-o", f"cache_dir={results / '.pytest_cache'}",
        f"--junitxml={junit}",
    ]
    with (results / "pytest-output.txt").open("w", encoding="utf-8") as log:
        with subprocess.Popen(
            command, cwd=tests_dir.parent, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
        ) as process:
            for line in process.stdout:
                log.write(line)
                print(line, end="", flush=True)
            exit_code = process.wait()

    lines = [f"Python: {sys.version.split()[0]}", f"Pytest exit code: {exit_code}"]
    try:
        root = ET.parse(junit).getroot()
        cases = list(root.iter("testcase"))
        counts = dict(passed=0, failed=0, errors=0, skipped=0, xfailed=0)
        for case in cases:
            skip = case.find("skipped")
            if case.find("failure") is not None:
                counts["failed"] += 1
            elif case.find("error") is not None:
                counts["errors"] += 1
            elif skip is not None:
                counts["xfailed" if skip.get("type") == "pytest.xfail" else "skipped"] += 1
            else:
                counts["passed"] += 1
        lines.append(f"Reported test cases: {len(cases)}")
        lines.extend(f"{name.capitalize()}: {count}" for name, count in counts.items())
        lines.append("Collection/setup errors are included in Errors; see console output for details.")
    except (OSError, ET.ParseError) as error:
        lines.append(f"JUnit results unavailable: {error}")
    summary = "\n".join(lines) + "\n"
    (results / "summary.txt").write_text(summary, encoding="utf-8")
    print("\n" + summary, end="")
    print(f"Reports: {results}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

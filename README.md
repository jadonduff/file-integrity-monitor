# file-integrity-monitor

A command line tool that establishes the integrity of file(s) using hash values to alert users when file(s) or a directory undergoes changes.

## Automated tests

Use Python 3.14 (the application's documented runtime):

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python tests/run_suite.py
```

With that environment activated, `python tests/run_suite.py` also runs the
complete suite. The runner works from any working directory when invoked by its
absolute path and exits with pytest's exit code. It prints verbose output and
replaces `pytest-output.txt`, `junit.xml`, and `summary.txt` under `tests/results/`.
Generated reports are ignored by Git; `.gitkeep` preserves the directory.
For focused debugging, run `.venv/bin/python -m pytest tests/test_files.py -v`.

Every application test copies `hashcheck.py` into its own pytest temp
directory and invokes it with the current Python interpreter. Pytest manages
temp directories using standard cleanup/retention policy. Tests use the standard
library w/ pytest and are suitable for docoker containers.

### Confirmed behavior and limitations

- Invalid argument counts and nonexistent paths print usage but exit with status
  zero. A nonexistent path also creates an empty cache. Three strict expected
  failures describe the desired nonzero exit behavior; separate passing tests
  check the current behavior.
- Directory hashes cover a ZIP representation of files. Empty subdirectory
  additions/deletions are invisible. A strict expected failure describes desired
  detection of additions. File modifications are detected.
- ZIP hashes include file timestamps, so a timestamp-only change can alter a
  directory hash. Individual file hashes cover contents only and ignore timestamp
  changes, despite the application's message mentioning metadata. Directory
  hashes should not be treated as portable content-only digests across systems.
- Malformed JSON and tested non-object cache values cause an uncaught exception
  and nonzero exit, leaving the cache untouched. Invalid digest strings in an
  otherwise valid cache are treated as previous hashes and replaced as changes.
  Cache contents are not validated before use.
- Unreadable files cause an uncaught `PermissionError` when permissions are
  enforced.
- Detected modifications automatically replace the saved baseline. A following
  unchanged scan reports no change.
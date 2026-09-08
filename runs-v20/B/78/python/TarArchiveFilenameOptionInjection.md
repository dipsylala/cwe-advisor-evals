## Verdict

exploitable

- **cwe_id**: CWE-78 (OS Command Injection)
- **location**: `backup.py`, line 9 (`subprocess.run(command, shell=False, check=True)`)
- **confidence**: high

## Source

`filenames` (the second parameter of `create_backup_archive(archive_path, filenames)`) is attacker-influenced input — a list of names to include in the archive. Each element of `filenames` is appended verbatim to the `command` list via `command.extend(filenames)` on line 6, with no check on its content or leading characters.

## Fix

### File: backup.py

```python
import subprocess


def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path, "--"]
    command.extend(filenames)

    # Fixed: "--" above tells tar's option parser that everything
    # after it is a positional operand, so a crafted filename can no
    # longer be read as an option/flag.
    subprocess.run(command, shell=False, check=True)
```

## Explanation

`subprocess.run(command, shell=False, ...)` with an argument list already prevents shell metacharacter injection, but it does not prevent argument injection (CWE-88): GNU tar parses every element of argv as a potential option unless told otherwise, so a filename such as `--checkpoint=1` or `--checkpoint-action=exec=sh script.sh` is read as a tar option rather than an archive member, letting an attacker who controls one entry of `filenames` make tar execute an arbitrary command (a well-known GTFOBins technique) even though no shell is ever invoked. The fix inserts a literal `--` argument immediately before the user-controlled operands. GNU tar (via `getopt_long`) treats `--` as the end-of-options marker, so every argument after it is taken as a literal file name regardless of its content, including one that starts with `-`. This closes the injection without rejecting or altering any legitimate filename — no valid archive member name is excluded by this change, unlike a `-`-prefix denylist/allowlist, which would.

## Behaviour changes

- Added a literal `"--"` element to the `command` list, positioned after `archive_path` and before the extended `filenames`. This is the only change; it is required by the fix (it is what makes tar stop treating subsequent arguments as options) and does not alter the archive produced for any legitimate filename, since `--` is not itself added as an archive member.
- Nothing else changed: `archive_path`, the `czf` mode flags, `shell=False`, and `check=True` are all preserved, so the function still raises `subprocess.CalledProcessError` on tar failure exactly as before, and still returns the same `CompletedProcess` object (discarded by the caller) as the original.
- **verification**: The fixed file was copied to a scratch location and checked with `python -m py_compile` (CPython 3.13.12) — no syntax errors, exit code 0. The behavior of GNU tar's `--` end-of-options handling was not executed against a live tar binary in this environment; it is a documented, standard `getopt_long` convention that GNU tar honors, matching the exact remediation pattern given in this repository's own `cwe/78/python` guidance for the `['tar', 'czf', archive, filename]` case.
- **assumptions**: `archive_path` is treated as a trusted, non-attacker-controlled value (per the finding's scope, which names only `filenames` as the injection vector), so it is left in place before the `--` marker rather than after it.

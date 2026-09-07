## Verdict
CONFIRMED - Option injection via tar filename operands.

## Source
Line 9 in `backup.py`: `subprocess.run()` passes user-supplied filenames directly as tar command arguments without restricting them. A filename starting with `-` (e.g., `-tf`) is interpreted as a tar option rather than a filename, allowing an attacker to change tar's behavior.

## Fix

### File: backup.py
```python
import subprocess


def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path, "--"]
    command.extend(filenames)

    # SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
    subprocess.run(command, shell=False, check=True)
```

## Explanation
The `--` argument is a standard end-of-options marker recognized by tar and most Unix utilities. It signals that all arguments following it should be treated as operands (filenames), not options, regardless of whether they start with a dash. This prevents a filename like `-xvf` from being misinterpreted as extract/verbose/file options.

While `shell=False` prevents shell metacharacter injection, it does not prevent option injection via argument position—a separate class of command injection. The `--` marker closes both gaps: it blocks leading-dash filenames from being parsed as options without requiring validation of each filename.

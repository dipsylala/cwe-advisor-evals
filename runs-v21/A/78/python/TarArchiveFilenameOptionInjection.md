## Verdict
CONFIRMED: CWE-78 option injection via `tar` command-line argument interpretation.

## Source
The vulnerability is at line 9 in `backup.py`:
```python
subprocess.run(command, shell=False, check=True)
```

The `command` array is built by extending with user-supplied `filenames` at line 6. While `shell=False` blocks shell metacharacter injection, it does not prevent `tar` from interpreting arguments starting with `-` as options rather than filenames. An attacker can craft a filename like `-C /etc` or `-X /tmp/exclude.txt` to inject `tar` options, bypassing intended file selection or causing directory traversal.

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
The fix adds `--` after the archive path and before the filenames. The `--` marker is a POSIX convention that tells `tar` (and nearly all command-line utilities) that all following arguments are operands, not options. This prevents filenames beginning with `-` from being misinterpreted as option flags. Even a malicious filename like `-C /etc` is now treated literally as a filename, eliminating the option injection vector.

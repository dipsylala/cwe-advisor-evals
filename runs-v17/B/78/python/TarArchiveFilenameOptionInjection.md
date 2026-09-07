## Verdict

Exploitable. A malicious filename passed via the `filenames` parameter can be interpreted as a tar option, enabling arbitrary command execution.

## Source

The `filenames` parameter to `create_backup_archive()` is attacker-controlled. It flows directly into the `command` array via `command.extend(filenames)` at line 6, then reaches the subprocess.run() sink at line 9 without validation or escaping.

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

The original code passes filenames as positional arguments to tar. A filename like `--to-command=malicious_script` is interpreted as a tar option rather than a filename to archive, allowing the attacker to inject arbitrary tar options and execute commands. The fix adds the `--` marker after the archive path, which is a POSIX standard convention that tells tar to stop processing options and treat all remaining arguments as operand filenames, even if they start with `-` or `--`. This closes the argument-injection vector while preserving the command's functionality for legitimate filenames.

## Behaviour changes

None. The `--` is a standard POSIX end-of-options marker that tar processes as part of its specification; it does not appear in the archived files and has no effect on the command's return value, output, or behavior for non-malicious inputs.

## Verdict

The vulnerability is confirmed. The code is susceptible to option injection through the `filenames` parameter. If an attacker supplies a filename starting with `-` (e.g., `-czf /tmp/malicious.tar`), it will be interpreted as a tar option rather than a filename, allowing command-line option injection.

## Source

```python
import subprocess


def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path]
    command.extend(filenames)

    # SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
    subprocess.run(command, shell=False, check=True)
```

## Fix

```python
import subprocess


def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path, "--"]
    command.extend(filenames)

    subprocess.run(command, shell=False, check=True)
```

## Explanation

The fix adds `"--"` as an explicit option separator before the filenames. The `--` marker tells tar (and most Unix command-line tools) that all arguments following it are operands, not options. This prevents attacker-supplied filenames from being misinterpreted as option flags, even if they start with `-` or contain characters that might otherwise be parsed as options.

For example, with this fix, a filename like `-czf /tmp/malicious.tar` will be treated as a literal filename to archive, not as tar command options. The `--` separator is the standard Unix convention for this boundary and is supported by all standard tar implementations.

## Verdict

exploitable

## Source

The `filenames` parameter to `create_backup_archive()` is untrusted user input passed directly into the command array without validation.

## Fix

### File: backup.py

```python
import subprocess


def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path, "--"]
    command.extend(filenames)

    subprocess.run(command, shell=False, check=True)
```

## Explanation

The vulnerability is argument injection (related to CWE-88). While `shell=False` with an argument list prevents shell metacharacter injection, it does not prevent a filename from being interpreted as a tar option flag. A malicious filename like `--to-command=rm -rf /` would be treated as a tar option rather than a filename. The fix adds `--` after the archive path, which signals to tar to stop processing options and treat all following arguments as filenames. This converts any value in the filenames list into data rather than a potential command flag, regardless of whether it starts with `-` or `--`.

## Behaviour changes

none

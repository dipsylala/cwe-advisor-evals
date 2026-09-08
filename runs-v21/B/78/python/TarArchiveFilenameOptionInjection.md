## Verdict

Exploitable

## Source

The `filenames` parameter passed to `create_backup_archive()`, which originates from untrusted input and is directly extended into the subprocess argument list without validation.

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

The original code uses `subprocess.run()` with `shell=False` and an argument list, which correctly prevents shell metacharacter injection. However, this protection does not prevent argument injection (CWE-88). A malicious value in the `filenames` list like `--to-command=rm -rf /` would be interpreted as a tar option rather than a filename, allowing the attacker to inject and execute arbitrary commands.

The fix adds a literal `--` argument after the archive filename. This is a standard POSIX convention that tells `tar` (and most command-line utilities) to stop processing options and treat all subsequent arguments as operands (filenames). This prevents any element in the `filenames` list from being misinterpreted as a tar option, closing the argument injection vulnerability while preserving all existing functionality.

## Behaviour changes

Adds a literal `--` argument to the command list. This has no functional impact on the command's behaviour—it is standard POSIX practice that stops tar from interpreting subsequent arguments as flags. The archive operation, output, and return value remain identical to the original code.

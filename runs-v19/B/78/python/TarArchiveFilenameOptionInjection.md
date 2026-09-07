## Verdict

Exploitable

## Source

**Data flow:**
- **Source**: The `filenames` parameter passed to `create_backup_archive()` - untrusted user-controlled input
- **Intermediate**: Line 6 extends the command list with filenames
- **Sink**: Line 9, `subprocess.run(command, shell=False, check=True)` - executes tar with the command arguments

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

The vulnerability is argument injection: `shell=False` prevents shell metacharacter injection but does not prevent argument injection. A filename like `--to-command=/bin/evil.sh` would be passed as a tar option rather than treated as a filename to archive, allowing option injection. The fix adds `--` (the POSIX end-of-options marker) between the archive path and the filenames. This ensures tar interprets everything following `--` as operands (filenames to archive), not as options, regardless of their content. Tar honors `--` per POSIX standard, so this prevents option injection without breaking legitimate filenames containing dashes, spaces, or other special characters.

## Behaviour changes

The command argument now includes `--` after the archive path. This is a standard POSIX marker that tells tar to treat everything following it as operands, not flags. The functional behavior is identical for legitimate filenames, but prevents option/argument injection. The return value, error handling, and output remain unchanged from the original.


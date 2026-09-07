## Verdict

Exploitable

## Source

**Source:** The `filenames` parameter (user-supplied list of filenames).

**Sink:** `subprocess.run(command, shell=False, check=True)` at line 9.

**Data flow:** The untrusted `filenames` list is directly extended into the command argument array via `command.extend(filenames)`, then passed to `subprocess.run()`. While `shell=False` prevents shell metacharacter injection, it does not prevent argument injection. A filename like `--to-command=malicious_command` is interpreted by tar as an option that specifies a command to run, not as a filename operand. This allows an attacker to execute arbitrary commands within the tar process.

## Fix

**Vulnerable code:**
```python
import subprocess

def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path]
    command.extend(filenames)

    # SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
    subprocess.run(command, shell=False, check=True)
```

**Fixed code:**
```python
import tarfile

def create_backup_archive(archive_path, filenames):
    with tarfile.open(archive_path, "w:gz") as tar:
        for filename in filenames:
            tar.add(filename)
```

## Explanation

The fix eliminates the subprocess call entirely by using Python's built-in `tarfile` module instead of shelling out to the tar command. This is the primary remediation pattern for CWE-78 when the command execution is incidental to the operation—in this case, the purpose is to create a tar archive, not to execute arbitrary commands. The tarfile API treats filenames as file paths, not command arguments, so values like `--to-command=...` are safely handled as literal filenames rather than interpreted as tar options. This removes the injection point entirely and provides the same functionality with no external process risk.

## Behaviour changes

- **Exception type:** Changes from `subprocess.CalledProcessError` to tarfile exceptions (`tarfile.ReadError`, `tarfile.CompressionError`, or `FileNotFoundError`). This is a beneficial change because it provides more specific error types for better exception handling.
- **Return value:** Both versions have an implicit return of `None`, so no functional change to callers.
- **stderr/stdout:** The original code passed stderr/stdout to the terminal via subprocess pass-through; the fixed code handles these internally via tarfile's logging. No output is lost or exposed.
- **File preservation:** The `tarfile.add()` method preserves file ownership and permissions by default (same as tar command), so no functional regression in archive contents.

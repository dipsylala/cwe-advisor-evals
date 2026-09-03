## Verdict

Exploitable. User-controlled filenames reach tar's argument parser without validation. A filename starting with `-` is interpreted as a tar option, allowing option injection.

## Source

The `filenames` parameter passed to `create_backup_archive()` is attacker-controlled and not validated before being incorporated into the command array.

## Fix

Insert `"--"` before extending the command with filenames to signal the end of option parsing. This forces tar to treat all subsequent arguments as operands (filenames) rather than options.

**Vulnerable code:**
```python
def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path]
    command.extend(filenames)

    # SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
    subprocess.run(command, shell=False, check=True)
```

**Fixed code:**
```python
def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path, "--"]
    command.extend(filenames)

    subprocess.run(command, shell=False, check=True)
```

## Explanation

While `shell=False` with an argument list prevents shell metacharacter injection, it does not prevent argument injection. A filename like `--to-command=whoami` is interpreted by tar as an option, not a filename, allowing attackers to inject arbitrary tar flags. The fix inserts `"--"` before the filenames, which is the standard Unix convention to end option parsing. Tar then treats all subsequent arguments strictly as operands, preventing option names from being misinterpreted as options.

## Behaviour changes

None. The fix preserves all aspects of the original sink contract. The subprocess call receives the same exit code handling, discards the same output (tar's stdout/stderr), and raises CalledProcessError identically on non-zero exits. Tar still receives the same archive path and filenames; the only change is that filenames can no longer be misinterpreted as options.

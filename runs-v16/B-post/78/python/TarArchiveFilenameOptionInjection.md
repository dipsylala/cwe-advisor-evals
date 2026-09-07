## Verdict
Exploitable

## Source
The `filenames` parameter passed to `create_backup_archive()` at line 4 is untrusted user input.

## Fix

**Vulnerable code:**
```python
def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path]
    command.extend(filenames)
    
    # SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
    subprocess.run(command, shell=False, check=True)  # Line 9: Vulnerable sink
```

**Fixed code:**
```python
def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path, "--"]
    command.extend(filenames)
    
    subprocess.run(command, shell=False, check=True)
```

## Explanation
This finding is argument injection (related to CWE-78). While `shell=False` prevents shell metacharacter injection, it does not prevent argument injection. An attacker can pass a filename like `--to-command=malicious_command` which tar interprets as an option rather than a filename, allowing arbitrary command execution. The fix adds `--` after the archive path, which is a standard POSIX convention signaling the end of option parsing. All arguments following `--` are treated as positional arguments (filenames) by tar, preventing option injection regardless of their content.

## Behaviour changes
None. The addition of `--` is purely a safety marker for tar's argument parser and does not alter the subprocess contract: `subprocess.run()` still returns a `CompletedProcess` instance, `check=True` still raises `CalledProcessError` on non-zero exit codes, and stdout/stderr still inherit from the parent process.

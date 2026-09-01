## Verdict

Exploitable. The `filename` parameter from the Flask request is directly interpolated into a shell command string and executed with `shell=True`, allowing arbitrary OS command execution via shell metacharacters.

## Source

Line 14: `filename = request.form["filename"]` — untrusted user input from Flask HTTP form data.

## Fix

**Vulnerable code (lines 18–23):**

```python
command = (
    f"libreoffice --headless --convert-to pdf "
    f"--outdir {OUTPUT_DIR} {input_path}"
)
# SAST FINDING: CWE-78 - OS Command Injection
subprocess.run(command, shell=True, check=True)
```

**Fixed code:**

```python
import re

# Validate filename to prevent command injection and path traversal
if not re.fullmatch(r'[a-zA-Z0-9._\-]+', filename):
    return "Invalid filename", 400

# Use argument list with shell=False to prevent command injection
subprocess.run(
    ["libreoffice", "--headless", "--convert-to", "pdf",
     "--outdir", OUTPUT_DIR, input_path],
    shell=False,
    check=True
)
```

## Explanation

The original code concatenates user-supplied `filename` into a shell command string executed with `shell=True`. This allows shell metacharacters in the filename (e.g., `; rm -rf /`) to be interpreted as separate commands. The fix uses three defensive layers: (1) input validation with `re.fullmatch()` to reject filenames containing anything other than alphanumeric characters, dots, hyphens, and underscores; (2) `subprocess.run()` with an argument list (`["libreoffice", ...]`) instead of a command string, which bypasses shell parsing; and (3) `shell=False` to invoke the program directly via `execve()` without shell interpretation. The combination of argument-list passing and `shell=False` eliminates shell metacharacter injection by preventing the shell from ever seeing the filename value.

## Behaviour changes

1. **Input validation added**: filename must match `[a-zA-Z0-9._\-]+` using `re.fullmatch()`. Requests with invalid filenames return HTTP 400 instead of attempting conversion. This rejects filenames containing shell metacharacters, path traversal sequences (`../`), and other unexpected characters.

2. **Shell execution disabled**: changed `shell=True` to `shell=False`. The command is now passed as an argument list directly to `execve()` rather than to a shell interpreter, preventing shell parsing of metacharacters.

3. **Command passed as argument array**: replaced f-string command concatenation with a list `["libreoffice", "--headless", ...]`, eliminating word-splitting and metacharacter expansion.

4. **Subprocess behavior preserved**: `check=True` still raises `CalledProcessError` on non-zero exit, maintaining the original error handling. stdout and stderr remain inherited from the parent process.

## Verdict

Exploitable. The `filename` parameter from untrusted user input (line 14, `request.form["filename"]`) is directly interpolated into a command string (lines 18–20) and executed with `subprocess.run(..., shell=True)` (line 23). An attacker can inject arbitrary shell commands by providing a crafted filename such as `"; rm -rf / #"`.

## Source

Line 14: `filename = request.form["filename"]` — untrusted user input from HTTP form data.

## Fix

**Vulnerable code:**
```python
filename = request.form["filename"]
input_path = f"{UPLOAD_DIR}/{filename}"
output_path = f"{OUTPUT_DIR}/{filename}.pdf"

command = (
    f"libreoffice --headless --convert-to pdf "
    f"--outdir {OUTPUT_DIR} {input_path}"
)
# SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
subprocess.run(command, shell=True, check=True)
```

**Fixed code:**
```python
import re

filename = request.form["filename"]

# Validate filename: allow only alphanumeric, dots, hyphens, underscores
if not re.fullmatch(r'[a-zA-Z0-9._-]+', filename):
    raise ValueError("Invalid filename")

input_path = f"{UPLOAD_DIR}/{filename}"
output_path = f"{OUTPUT_DIR}/{filename}.pdf"

subprocess.run(
    ["libreoffice", "--headless", "--convert-to", "pdf", "--outdir", OUTPUT_DIR, input_path],
    shell=False,
    check=True
)
```

## Explanation

The fix eliminates the injection vulnerability by removing `shell=True` and string concatenation. The command and its arguments are now passed as a list to `subprocess.run(..., shell=False)`, which prevents the shell from interpreting special characters in the filename. A strict regex allowlist (`re.fullmatch(r'[a-zA-Z0-9._-]+', filename)`) validates the filename before use, rejecting any path traversal attempts or shell metacharacters. If the filename does not match the allowlist, a `ValueError` is raised rather than proceeding to the vulnerable sink.

## Behaviour changes

- `shell=False` eliminates shell metacharacter interpretation; the filename is passed as a literal argument to the libreoffice process.
- Filename validation adds a new check that raises `ValueError` for invalid input; previously such input would be passed directly to the shell.
- No change to the return value or error handling — `subprocess.run()` with `check=True` still raises `CalledProcessError` on non-zero exit, preserving the original error contract.
- The fixed code supplies `stdout` and `stderr` implicitly as `None` (the default), which means subprocess writes directly to the parent's streams, the same as the original.

## Verdict
exploitable

## Source
`request.form["filename"]` at line 14 - untrusted user input from form data

## Fix

**Vulnerable code:**
```python
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

# Validate filename to prevent path traversal and command injection
if not re.fullmatch(r'[a-zA-Z0-9._\-]+', filename):
    raise ValueError("Invalid filename format")

input_path = f"{UPLOAD_DIR}/{filename}"
output_path = f"{OUTPUT_DIR}/{filename}.pdf"

# Use subprocess with argument list and shell=False to prevent OS command injection
subprocess.run([
    "libreoffice", "--headless", "--convert-to", "pdf",
    "--outdir", OUTPUT_DIR, input_path
], shell=False, check=True)
```

(Add `import re` to the imports at the top of the file)

## Explanation

The fix eliminates the shell injection vulnerability by using `shell=False` and passing arguments as a list instead of a command string. This prevents the shell from interpreting metacharacters or special elements in the filename. The added input validation with `re.fullmatch()` enforces a strict allowlist of safe filename characters (alphanumeric, dots, underscores, hyphens), rejecting any filename containing path traversal sequences or shell metacharacters before it reaches the subprocess call. This defense-in-depth approach stops both shell metacharacter injection and path traversal attacks.

## Behaviour changes

- `subprocess.run()` now uses `shell=False` instead of `shell=True`, eliminating shell interpretation of the command line
- Command and arguments are passed as a list instead of a single string - each element is treated literally by the OS
- Input validation is added to reject filenames with characters outside the safe allowlist, raising `ValueError` for invalid input
- All changes preserve the original functionality: libreoffice still executes with the same arguments and produces the same output (PDF file), which is then served via `send_file()`

## Verdict

Exploitable

## Source

`request.form["filename"]` at line 14, untrusted user input from Flask form data

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

# Add this pattern near the top with other module-level definitions
FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

# In the convert_document function, add validation before command construction:
filename = request.form["filename"]

# Validate filename to prevent path traversal and argument injection
if not FILENAME_PATTERN.fullmatch(filename):
    raise ValueError("Invalid filename format")

input_path = f"{UPLOAD_DIR}/{filename}"
output_path = f"{OUTPUT_DIR}/{filename}.pdf"

# Use subprocess with argument list and shell=False to prevent command injection
subprocess.run(
    ["libreoffice", "--headless", "--convert-to", "pdf",
     "--outdir", OUTPUT_DIR, input_path],
    shell=False,
    check=True
)
```

## Explanation

The original code concatenates untrusted user input (`filename`) directly into a shell command string and passes it to `subprocess.run()` with `shell=True`. This allows an attacker to inject arbitrary shell commands by providing a crafted filename (e.g., `document.txt; rm -rf /`). The fix uses three complementary defences: (1) replace `shell=True` with an argument list and `shell=False`, which prevents the shell from interpreting metacharacters in the filename argument; (2) add input validation using a strict allowlist pattern that only permits alphanumeric characters, dots, hyphens, and underscores, rejecting filenames with path traversal sequences (`../`) or shell metacharacters; (3) pass the filename as a separate argument in the subprocess argument array rather than embedded in a command string. Together, these eliminate command injection by preventing shell interpretation and by refusing filenames that could be interpreted as additional options or arguments by the target program.

## Behaviour changes

- **New import**: Added `re` module for filename validation pattern (standard library, no dependency required)
- **New module-level constant**: Added `FILENAME_PATTERN` regex to validate filenames before use
- **Added validation**: The function now raises `ValueError` if the filename does not match the allowlist pattern, whereas the original code would have accepted and processed invalid filenames (this is a security improvement that changes the input contract)
- **Argument structure**: Changed from a single command string to an argument list passed to `subprocess.run()`, which prevents shell metacharacter interpretation but otherwise produces identical LibreOffice invocation
- **Removed shell=True**: The shell parameter is now `False` (or omitted, since `False` is the default); this changes the execution context from shell to direct program invocation, eliminating shell injection but preserving the exact command and arguments passed to LibreOffice
- **Return value and output**: The function's return value (`send_file(output_path)`) and overall behavior remain unchanged; the PDF file is still produced at the same location and returned to the client

## Verification

Syntax validation with Python compiler:
```
python -m py_compile ConvertFileSubprocessShell.py
```

The fixed code was validated to confirm:
- All new names (`re` module, `FILENAME_PATTERN`, `ValueError`) are standard library or built-in
- All subprocess.run() arguments (list format, `shell=False`, `check=True`) match the standard library signature
- The argument list structure correctly passes each component as a separate element
- No syntax errors or undefined names

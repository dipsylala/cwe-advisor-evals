## Verdict

exploitable

## Source

`request.form["filename"]` at line 14 - untrusted user input from POST form data

## Fix

**Vulnerable code:**

```python
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/data/uploads"
OUTPUT_DIR = "/var/data/converted"


@app.route("/convert", methods=["POST"])
def convert_document():
    """Convert an uploaded document to PDF using the installed LibreOffice CLI."""
    filename = request.form["filename"]
    input_path = f"{UPLOAD_DIR}/{filename}"
    output_path = f"{OUTPUT_DIR}/{filename}.pdf"

    command = (
        f"libreoffice --headless --convert-to pdf "
        f"--outdir {OUTPUT_DIR} {input_path}"
    )
    # VULNERABLE: shell=True interprets metacharacters in command string
    subprocess.run(command, shell=True, check=True)

    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

**Fixed code:**

```python
import re
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/data/uploads"
OUTPUT_DIR = "/var/data/converted"


@app.route("/convert", methods=["POST"])
def convert_document():
    """Convert an uploaded document to PDF using the installed LibreOffice CLI."""
    filename = request.form["filename"]
    
    # Validate filename: prevent argument injection and path traversal
    if not re.fullmatch(r'[a-zA-Z0-9._-]+', filename):
        raise ValueError("Invalid filename: contains disallowed characters")
    
    input_path = f"{UPLOAD_DIR}/{filename}"
    output_path = f"{OUTPUT_DIR}/{filename}.pdf"

    # FIXED: Use subprocess.run with shell=False and argument list
    subprocess.run([
        "libreoffice", "--headless", "--convert-to", "pdf",
        "--outdir", OUTPUT_DIR, input_path
    ], check=True)

    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix eliminates the OS command injection by replacing shell string concatenation with a parameterized argument list. Instead of `subprocess.run(command, shell=True)` which passes a single string to the shell for interpretation, the code now uses `subprocess.run([...], check=True)` with `shell=False` (the default), passing the command and its arguments as a list. This prevents the shell from interpreting metacharacters like `;`, `&&`, `|`, backticks, or `$()` in the filename. Additionally, strict input validation using `re.fullmatch(r'[a-zA-Z0-9._-]+', filename)` prevents argument injection attacks where a filename like `--to-stdout` could be misinterpreted as a LibreOffice option. The validation rejects any filename containing directory traversal sequences or special characters, ensuring only safe characters reach the subprocess.

## Behaviour changes

- **shell parameter**: Changed from `True` to `False` (default) - the shell no longer interprets the command string, eliminating shell metacharacter injection
- **command format**: Changed from a single concatenated string to a list of arguments - arguments are passed directly to libreoffice without shell parsing
- **input validation**: Added strict allowlist validation of filename using `re.fullmatch()` - filenames must contain only alphanumeric characters, dots, hyphens, and underscores, preventing both shell injection and argument injection
- **error handling**: Invalid filenames now raise `ValueError` during validation instead of being passed to subprocess where they would cause libreoffice to fail; this allows the application to reject malicious input before attempting process execution
- **import changes**: Added `import re` for regex validation

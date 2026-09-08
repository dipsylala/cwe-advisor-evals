## Verdict

Exploitable. The untrusted filename parameter flows directly into the subprocess command string with shell=True, allowing an attacker to inject arbitrary shell commands.

## Source

Line 14: `filename = request.form["filename"]`

The `filename` parameter is untrusted user input received from an HTTP form submission in the Flask request. It is not validated or sanitized before use.

## Sink

Line 23: `subprocess.run(command, shell=True, check=True)`

The vulnerability is triggered at this point. The command string (constructed on lines 18-21) contains the untrusted filename directly concatenated with libreoffice arguments. With `shell=True`, the shell interprets special characters and metacharacters as commands, allowing injection. For example, a filename like `test.doc; rm -rf /` would result in the libreoffice command followed by a rm command executed by the shell.

## Fix

### File: ConvertFileSubprocessShell.py

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
    
    # Reject path traversal attempts
    if ".." in filename or filename.startswith("/"):
        return "Invalid filename", 400
    
    input_path = f"{UPLOAD_DIR}/{filename}"
    output_path = f"{OUTPUT_DIR}/{filename}.pdf"

    # Use argument list with shell=False to prevent OS command injection
    subprocess.run(
        ["libreoffice", "--headless", "--convert-to", "pdf",
         "--outdir", OUTPUT_DIR, input_path],
        shell=False,
        check=True
    )

    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix eliminates OS command injection by replacing the shell string with an argument array and setting `shell=False` (the default, but made explicit for clarity). By using an argument list, the subprocess module no longer invokes a shell to parse the command. Each element in the list is passed directly to the operating system as a separate argument, preventing shell metacharacters (`;`, `|`, `&`, `>`, `<`, `$()`, backticks, etc.) from being interpreted as special. The filename becomes just another argument value, not part of a shell-parsed string. Secondary validation rejects path traversal attempts (`..` and leading `/`) to defend against CWE-22, though the argument array structure already prevents shell-based directory escape attacks.

## Behaviour changes

- **Added validation:** Lines 17-18 check for `..` and leading `/` in the filename and return a 400 error if found. This rejects legitimate filenames with `..` or leading `/`, but these patterns are not typical in user-supplied filenames for document conversion and the rejection is appropriate for this use case. The validation prevents path traversal attacks before the file operation.
- **Changed sink:** `subprocess.run()` now uses an argument list instead of a shell string and sets `shell=False` explicitly. The behavior is identical from the caller's perspective—the subprocess still spawns libreoffice with the same arguments—but the mechanism is now safe from injection. The `check=True` parameter behavior is unchanged: it still raises `CalledProcessError` on non-zero exit.
- **No change to return value:** The function still returns the same object from `send_file()`, so callers see identical behavior.

Syntax verification: `python -m py_compile` passed without errors.

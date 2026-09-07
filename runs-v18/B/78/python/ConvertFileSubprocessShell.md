## Verdict

Exploitable

## Source

`filename = request.form["filename"]` (line 14) — untrusted user input from HTTP POST request form parameter

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
    input_path = f"{UPLOAD_DIR}/{filename}"
    output_path = f"{OUTPUT_DIR}/{filename}.pdf"

    command = [
        "libreoffice",
        "--headless",
        "--convert-to", "pdf",
        "--outdir", OUTPUT_DIR,
        input_path
    ]
    subprocess.run(command, shell=False, check=True)

    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

## Explanation

The vulnerability stems from passing an untrusted filename directly into a shell command string executed with `shell=True`. An attacker can inject arbitrary shell commands via special characters in the filename parameter (e.g., `test.pdf"; rm -rf /`). The fix eliminates shell interpretation by converting the command from a string concatenation to an argument list and setting `shell=False`. With `shell=False`, subprocess passes the arguments directly to the libreoffice executable without invoking a shell interpreter, preventing shell metacharacters in the filename from being interpreted as command separators or operators. The untrusted `input_path` becomes a single argument to the libreoffice program and cannot break out of its argument context.

## Behaviour changes

None. The `subprocess.run()` call with `shell=False` and an argument list produces identical behavior to the original: it invokes libreoffice with the same arguments in the same order, returns the same value (None), and raises CalledProcessError on failure when `check=True` is set. The Flask endpoint still returns `send_file(output_path)` unchanged.

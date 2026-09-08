## Verdict

The vulnerability is confirmed. The `filename` parameter from user input is embedded into a shell command string and executed via `subprocess.run()` with `shell=True`, allowing OS command injection.

## Source

```python
filename = request.form["filename"]
input_path = f"{UPLOAD_DIR}/{filename}"
output_path = f"{OUTPUT_DIR}/{filename}.pdf"

command = (
    f"libreoffice --headless --convert-to pdf "
    f"--outdir {OUTPUT_DIR} {input_path}"
)
subprocess.run(command, shell=True, check=True)
```

The attacker-controlled `filename` is concatenated into the command string. With `shell=True`, shell metacharacters in the filename (e.g., `; rm -rf /`) are interpreted by the shell, allowing arbitrary command execution.

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
    subprocess.run(command, check=True)

    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

## Explanation

Replace the shell command string with an argument list passed to `subprocess.run()`. By default, `shell=False`, so the `libreoffice` program receives arguments directly without shell interpretation. This prevents shell metacharacters in `filename` from being evaluated as command syntax.

The fix restructures the command from a single string into a list where each element is a separate argument:
- Program name: `"libreoffice"`
- Flags and their values as separate list elements
- The user-controlled `input_path` is passed as a plain argument, not interpreted by the shell

Even if `filename` contains shell metacharacters, they are passed literally to `libreoffice` as part of the filename, which is the intended behavior.

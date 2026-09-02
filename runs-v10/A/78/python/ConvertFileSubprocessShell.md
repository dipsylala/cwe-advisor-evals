## Verdict
Confirmed. The code constructs an OS command from user-supplied input and executes it with shell interpretation enabled, allowing arbitrary command injection via the `filename` parameter.

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

The vulnerability is at line 23: `subprocess.run(command, shell=True, check=True)`. The `filename` parameter from the HTTP request is interpolated directly into the `command` string. When `shell=True` is used, the shell interprets special characters in the string, allowing an attacker to inject arbitrary commands. For example, a filename like `document.txt; rm -rf /` would execute the `rm` command.

## Fix
```python
filename = request.form["filename"]
input_path = f"{UPLOAD_DIR}/{filename}"
output_path = f"{OUTPUT_DIR}/{filename}.pdf"

subprocess.run(
    ["libreoffice", "--headless", "--convert-to", "pdf", "--outdir", OUTPUT_DIR, input_path],
    shell=False,
    check=True
)
```

Replace the shell string with an argument array and set `shell=False` (or omit it, as `False` is the default). Each command-line argument is a separate list element, preventing the shell from interpreting special characters in the filename. The `subprocess` module passes the arguments directly to the underlying OS without shell processing.

## Explanation
OS command injection occurs when user input is embedded into a command string executed with shell interpretation. The original code uses `shell=True`, which causes `subprocess.run()` to invoke `/bin/sh` (or `cmd.exe` on Windows) to parse and execute the command string. If an attacker controls any part of that string (in this case, the `filename`), they can inject shell metacharacters like `;`, `|`, `&`, `$(...)`, or backticks to execute arbitrary commands with the application's privileges.

The fix prevents this by:
1. Passing a list of arguments instead of a single shell string
2. Setting `shell=False` to bypass shell parsing entirely
3. Relying on the OS to execute the target program directly with the provided arguments

With this approach, special characters in the filename are treated as literal characters, not shell operators, and cannot be used to inject additional commands. The example filename `document.txt; rm -rf /` is now passed as a single, literal filename argument that libreoffice will not find (and no `rm` command is executed).

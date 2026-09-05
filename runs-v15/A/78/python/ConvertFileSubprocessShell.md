## Verdict
**Confirmed vulnerability.** The code constructs an OS command by string interpolation of user-controlled input (`filename` from `request.form`) and passes it to `subprocess.run()` with `shell=True`, allowing an attacker to inject arbitrary shell commands.

## Source
Line 23 in `ConvertFileSubprocessShell.py`:
```python
subprocess.run(command, shell=True, check=True)
```

The command string on lines 18–21 is constructed via f-string interpolation that includes `filename` (line 14) and `input_path` (line 15), both derived directly from user input without sanitization. The `shell=True` parameter causes the shell to parse metacharacters in the string, giving an attacker command-injection entry points (e.g., `;`, `|`, `&`, `$()`, backticks).

**Attack vector:** An attacker supplies a filename like `test.docx; rm -rf /tmp` or `test.docx$(whoami)` via the POST form, and the shell executes the injected commands alongside the intended `libreoffice` invocation.

## Fix
Replace the shell-based invocation with an argument list passed to `subprocess.run()` without `shell=True`:

```python
subprocess.run(
    ["libreoffice", "--headless", "--convert-to", "pdf", 
     "--outdir", OUTPUT_DIR, input_path],
    check=True
)
```

Remove the command variable and the `shell=True` parameter. By passing a list of arguments directly, the subprocess module treats each element as a literal argument to the program, not as a shell string to be parsed—metacharacters are no longer interpreted.

Additionally, validate or constrain the filename to prevent path traversal or other misuse:
```python
import os
filename = request.form["filename"]
# Reject absolute paths and path traversal attempts
if not filename or filename.startswith("/") or ".." in filename:
    return "Invalid filename", 400
```

## Explanation
OS command injection occurs when untrusted input is embedded into a command string executed by a shell. The `shell=True` parameter in `subprocess.run()` invokes `/bin/sh` (or `cmd.exe` on Windows), which interprets special characters like `;`, `|`, `&`, `$()`, and backticks as operators. An attacker can chain unrelated commands (`;`), pipe output, or embed command substitutions to execute arbitrary code.

The fix uses an argument list instead, which bypasses shell parsing. Each element in the list is passed directly to the target executable without interpretation of metacharacters. This is the recommended approach for all subprocess calls that accept user input. Additionally, filename validation rejects traversal patterns and absolute paths, providing defense-in-depth against path-based exploits.

## Verdict

**CWE-78 confirmed at line 23.** The code constructs a shell command using string interpolation with unsanitized user input (`filename` from `request.form`), then passes `shell=True` to `subprocess.run()`, enabling OS command injection.

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

An attacker can inject shell metacharacters via the `filename` parameter—for example, `"document.txt; malicious-command"` will execute both the libreoffice conversion and the attacker's command.

## Fix

```python
filename = request.form["filename"]
input_path = f"{UPLOAD_DIR}/{filename}"
output_path = f"{OUTPUT_DIR}/{filename}.pdf"

subprocess.run(
    ["libreoffice", "--headless", "--convert-to", "pdf", "--outdir", OUTPUT_DIR, input_path],
    check=True
)
```

Replace the shell command string with an argument list. Omit `shell=True`—`subprocess.run()` defaults to `shell=False`, which passes arguments directly to the process without shell interpretation. Shell metacharacters in `filename` are now treated as literal characters, not special syntax.

## Explanation

**Root cause:** String interpolation of user input into a shell command combined with `shell=True` allows an attacker to break out of the intended command and inject arbitrary OS commands.

**Why this fix works:** Passing arguments as a list to `subprocess.run()` (with the default `shell=False`) bypasses the shell entirely. The process receives the arguments directly, and special characters like `;`, `|`, `&`, and backticks have no special meaning—they are passed as-is to the target program, which treats them as literal data.

**Defense in depth:** If `libreoffice` needs additional hardening, validate `filename` against a strict allowlist (e.g., alphanumeric, `.`, `-`) before use. However, the argument-list fix alone closes the injection vector.

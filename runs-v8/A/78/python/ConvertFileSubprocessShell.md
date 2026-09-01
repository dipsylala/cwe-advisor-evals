## Verdict

Confirmed. The code executes an attacker-controlled command string through the shell, enabling OS command injection via the `filename` request parameter.

## Source

Line 14: `filename = request.form["filename"]` — user-supplied input from the request form.

Line 15: `input_path = f"{UPLOAD_DIR}/{filename}"` — unsanitized filename embedded in a file path.

Line 18-20: Command string constructed by string interpolation, incorporating both `input_path` and `OUTPUT_DIR`.

Line 23: `subprocess.run(command, shell=True, check=True)` — the command string is executed through the shell, where special characters in `input_path` are interpreted as shell metacharacters.

## Fix

Pass the command and arguments as a list to `subprocess.run()`, omitting `shell=True`:

```python
subprocess.run([
    "libreoffice",
    "--headless",
    "--convert-to", "pdf",
    "--outdir", OUTPUT_DIR,
    input_path
], check=True)
```

## Explanation

Using `shell=True` with a constructed command string enables shell metacharacter injection. An attacker who controls any part of the command string can inject shell operators (`; | & $ ()` etc.) to execute arbitrary commands.

When arguments are passed as a list, they are treated as literal operands and delivered directly to the `libreoffice` process without shell interpretation. The injection vectors — semicolon for command chaining, backticks for command substitution, `$()` for variable expansion, and pipe operators — are all neutralized because the shell never parses them.

This also eliminates the need to manually quote or escape the arguments, making the code clearer and more maintainable.

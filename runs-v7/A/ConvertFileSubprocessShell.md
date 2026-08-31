## Verdict

Confirmed. The code passes unsanitized user input directly into a shell command string.

## Source

Line 23 executes `subprocess.run(command, shell=True)` where the `command` string is constructed via string interpolation from line 18-20. The `filename` parameter from line 14 (`request.form["filename"]`) is user-controlled, untrusted, and passed through `input_path` without validation or escaping into the shell command. An attacker can inject shell metacharacters or command separators.

## Fix

Replace the vulnerable subprocess call with an argument list and remove shell execution:

```python
subprocess.run(
    ["libreoffice", "--headless", "--convert-to", "pdf",
     "--outdir", OUTPUT_DIR, input_path],
    check=True
)
```

Remove the `command` string variable entirely.

## Explanation

By passing arguments as a list to `subprocess.run()` instead of invoking a shell, the operating system directly executes `libreoffice` with the specified arguments without shell parsing. Each list element is treated as a literal argument, preventing the shell from interpreting special characters in `filename` (such as `;`, `|`, `$()`, or backticks) as command operators. An attacker-supplied filename like `test.txt; rm -rf /` is passed to libreoffice as a single literal string, not parsed as a separate command.


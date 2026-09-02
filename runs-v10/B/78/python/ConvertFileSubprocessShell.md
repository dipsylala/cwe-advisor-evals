## Verdict

The finding is confirmed. OS Command Injection is present on line 23 where an untrusted filename from `request.form["filename"]` is concatenated into a command string and executed via `subprocess.run(..., shell=True)`.

## Source

`filename = request.form["filename"]` on line 14 is untrusted user input sourced from an HTTP form. This value flows through lines 15-20 to construct a shell command string that is executed on line 23 without any validation or escaping.

The data path:
1. Line 14: Attacker-controlled `filename` parameter received from HTTP form
2. Line 15: `input_path` constructed by interpolating `filename` into a file path
3. Lines 18-21: `command` string constructed by interpolating `input_path` into a shell command
4. Line 23: `subprocess.run(command, shell=True, ...)` executes the unsanitized command string via a shell

## Fix

Replace the string-based command with an argument list and `shell=False`:

```python
subprocess.run([
    "libreoffice",
    "--headless",
    "--convert-to", "pdf",
    "--outdir", OUTPUT_DIR,
    input_path
], check=True)
```

Change line 23 from:
```python
subprocess.run(command, shell=True, check=True)
```

To:
```python
subprocess.run([
    "libreoffice",
    "--headless",
    "--convert-to", "pdf",
    "--outdir", OUTPUT_DIR,
    input_path
], check=True)
```

And remove lines 18-21 that construct the `command` string, since it is no longer needed.

## Explanation

The fix eliminates shell interpretation by passing arguments as a list to `subprocess.run()` with the default `shell=False`. When arguments are provided as a list rather than a string, the subprocess module passes them directly to the program without invoking a shell parser, which prevents shell metacharacters in the filename (e.g., `; rm -rf /`, `$(command)`, backticks, pipes) from being interpreted as shell syntax. Each element of the list becomes a separate argument to the libreoffice binary, so the filename value can no longer escape its argument position.

The fix preserves the original behavior: libreoffice still receives the same arguments, performs the PDF conversion, and the HTTP response still downloads the file. The `check=True` parameter behavior is unchanged—subprocess.run() still raises CalledProcessError on non-zero exit codes.

## Behaviour changes

None. The subprocess call produces identical output and behavior, with the exception that shell metacharacters in filenames no longer trigger command injection—they are now treated as literal characters within the filename argument, which is the correct behavior.

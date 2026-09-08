## Verdict

CONFIRMED: CWE-78 OS Command Injection at line 29.

## Source

`report_id` parameter (line 16) is user-controlled input from the caller (e.g. web request query parameter) with no validation before reaching the shell sink.

## Fix

Replace `subprocess.Popen()` with `shell=True` and string concatenation with `subprocess.run()` using an argument list and `shell=False`. Validate `report_id` against its expected alphanumeric format before any use.

### File: PopenShellBatchWindows.py

```python
"""Windows report export service.

Runs a bundled .bat script (export_report.bat) that wraps the legacy
reporting toolchain used on the deployment host. The script accepts a
report identifier and writes the rendered report to the shared output
folder.
"""

import os
import re
import subprocess

SCRIPTS_DIR = r"C:\ReportingService\scripts"
OUTPUT_DIR = r"C:\ReportingService\output"


def export_report(report_id: str) -> str:
    """Invoke the bundled export_report.bat for the given report id.

    report_id is supplied by the caller (e.g. taken from a web request
    query parameter) and is expected to be a short alphanumeric report
    key. Only alphanumeric characters and underscores are accepted;
    other characters are rejected to prevent command injection.
    """
    # Validate report_id format before passing to subprocess
    if not re.fullmatch(r'[a-zA-Z0-9_]+', report_id):
        raise ValueError(f"Invalid report_id format: {report_id}")
    
    bat_path = os.path.join(SCRIPTS_DIR, "export_report.bat")
    output_path = os.path.join(OUTPUT_DIR, report_id + ".pdf")

    # Use subprocess.run() with argument list and shell=False to prevent
    # command injection and shell interpretation of special characters
    proc = subprocess.run(
        [bat_path, report_id, output_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False
    )

    if proc.returncode != 0:
        raise RuntimeError(f"export_report.bat failed: {proc.stderr.decode(errors='replace')}")

    return output_path
```

## Explanation

The original code built a shell command string by concatenating user-supplied `report_id` into it, then passed that string to `subprocess.Popen()` with `shell=True`, allowing cmd.exe to interpret shell metacharacters in the input as commands (command injection).

The fix eliminates the shell layer by:
1. **Using `subprocess.run()` with `shell=False`** - Passes the command and arguments as a list, preventing the shell from interpreting metacharacters in the arguments as special syntax.
2. **Adding input validation** - Validates `report_id` against its documented format (alphanumeric + underscore) using `re.fullmatch()`, which rejects characters that could be used for injection or interpreted as command-line flags. The fullmatch ensures the entire string matches the pattern, not just a prefix.
3. **Argument list separation** - The bat file path, report ID, and output path are now separate list elements, each treated as a literal argument to the program.

The fix preserves the original behavior: returns `output_path` on success, raises `RuntimeError` with stderr on subprocess failure. The validation layer rejects malformed input early before it reaches the subprocess sink, providing defense-in-depth per CWE-78 guidance.

## Behaviour changes

1. **Input validation**: Caller must supply a report_id matching `[a-zA-Z0-9_]+`; other formats now raise `ValueError`. This matches the documented requirement ("short alphanumeric report key") and closes the injection vector.
2. **Process API**: Switched from `Popen.communicate()` to `subprocess.run()`. Both block until completion and capture stdout/stderr identically; the behavioral difference is invisible to callers.
3. **Error handling**: Unchanged - still raises `RuntimeError` with stderr when subprocess fails, and returns output_path on success.

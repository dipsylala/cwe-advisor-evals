## Verdict

CONFIRMED: OS Command Injection via string concatenation into subprocess.Popen() with shell=True. The report_id parameter flows directly from the caller into a command string without validation, allowing arbitrary shell command injection on line 29.

## Source

**File:** PopenShellBatchWindows.py, line 16-29  
**Taint Source:** `report_id` parameter (supplied by caller from web request)  
**Taint Sink:** `subprocess.Popen(command, shell=True, ...)` at line 29

The `report_id` flows through:
1. Parameter input (line 16)
2. String concatenation into `command` (line 26: `command = bat_path + " " + report_id + " " + output_path`)
3. Passed to subprocess.Popen() with shell=True (line 29)

## Fix

Replace string concatenation and shell=True with subprocess.run() using an argument list and shell=False, with strict input validation:

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
    key. Input validation ensures only safe characters reach the process.
    """
    # Validate report_id: only allow alphanumeric characters
    if not re.fullmatch(r'[a-zA-Z0-9]+', report_id):
        raise ValueError("Invalid report_id: must contain only alphanumeric characters")
    
    bat_path = os.path.join(SCRIPTS_DIR, "export_report.bat")
    output_path = os.path.join(OUTPUT_DIR, report_id + ".pdf")

    # Use subprocess.run() with shell=False and argument list instead of string
    # concatenation to prevent OS command injection. On Windows, batch files
    # require cmd.exe /c, which is passed as a separate argument.
    proc = subprocess.run(
        ['cmd.exe', '/c', bat_path, report_id, output_path],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if proc.returncode != 0:
        raise RuntimeError(f"export_report.bat failed: {proc.stderr.decode(errors='replace')}")

    return output_path
```

## Explanation

The vulnerability stems from passing untrusted input to a shell via string concatenation. The original code concatenates `report_id` directly into the command string and passes it to `subprocess.Popen(..., shell=True)`, which invokes a shell to parse the entire command. An attacker can inject arbitrary shell commands by including special characters like `&`, `|`, `;`, or `$()`.

The fix addresses this in three ways:

1. **Eliminate shell parsing:** Use `subprocess.run()` with `shell=False` and pass arguments as a list. This prevents the shell from interpreting special characters within individual arguments.

2. **Windows batch file handling:** Windows batch files (.bat/.cmd) require cmd.exe to execute. The fix explicitly passes `['cmd.exe', '/c', bat_path, report_id, output_path]` as a list with shell=False, ensuring arguments are passed directly to cmd.exe without prior shell interpretation.

3. **Input validation:** Add strict allowlist validation using `re.fullmatch(r'[a-zA-Z0-9]+', report_id)` to ensure only alphanumeric characters are accepted. This serves as a secondary defense: even if cmd.exe re-parses the arguments, validated alphanumeric values cannot contain shell metacharacters or be misinterpreted as command options.

The fix preserves the original behavior: it still invokes the batch file, captures stdout/stderr, checks the return code, and returns the output_path string.

## Behaviour changes

- **Input validation added:** The function now raises `ValueError` if report_id contains non-alphanumeric characters. This is a stricter contract than the original (which accepted any string), but aligns with the documented expectation that report_id should be "a short alphanumeric report key."
- **Process API changed:** Switched from `subprocess.Popen(...).communicate()` to `subprocess.run(...)`. Functionally equivalent but subprocess.run() is simpler and more Pythonic.
- **Error handling preserved:** The function continues to raise RuntimeError with stderr output on non-zero exit codes.
- **Return value unchanged:** Still returns output_path (the destination file path).

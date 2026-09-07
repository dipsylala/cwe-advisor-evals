## Verdict

Real vulnerability. Untrusted `report_id` is concatenated into a command string and executed with `shell=True`, allowing OS command injection.

## Source

Function parameter `report_id` at line 16, supplied by caller from web request query parameter, with no validation before reaching the sink.

## Fix

### File: PopenShellBatchWindows.py

```python
"""Windows report export service.

Runs a bundled .bat script (export_report.bat) that wraps the legacy
reporting toolchain used on the deployment host. The script accepts a
report identifier and writes the rendered report to the shared output
folder.
"""

import os
import subprocess
import re

SCRIPTS_DIR = r"C:\ReportingService\scripts"
OUTPUT_DIR = r"C:\ReportingService\output"


def export_report(report_id: str) -> str:
    """Invoke the bundled export_report.bat for the given report id.

    report_id is supplied by the caller (e.g. taken from a web request
    query parameter) and must be a short alphanumeric report key.
    """
    # Validate report_id against strict allowlist (alphanumeric only)
    if not re.fullmatch(r'[a-zA-Z0-9]+', report_id):
        raise ValueError(f"Invalid report_id: {report_id}")
    
    bat_path = os.path.join(SCRIPTS_DIR, "export_report.bat")
    output_path = os.path.join(OUTPUT_DIR, report_id + ".pdf")

    # Use subprocess.run with argument list and shell=False to prevent command injection
    # Arguments are passed separately, preventing shell metacharacter interpretation
    proc = subprocess.run(
        [bat_path, report_id, output_path],
        shell=False,
        capture_output=True
    )

    if proc.returncode != 0:
        raise RuntimeError(f"export_report.bat failed: {proc.stderr.decode(errors='replace')}")

    return output_path
```

## Explanation

The vulnerability is closed by three complementary changes:

1. **Eliminate shell interpretation** (primary defence): Changed from `subprocess.Popen(command, shell=True)` to `subprocess.run([...], shell=False)`. With `shell=False`, the arguments are passed directly to the operating system without being re-parsed by cmd.exe, preventing shell metacharacter injection.

2. **Parameterized API**: Arguments are passed as a list `[bat_path, report_id, output_path]` instead of concatenated into a single command string. This structural separation ensures the shell parser never sees the arguments as part of the command syntax.

3. **Input validation (secondary defence)**: Added `re.fullmatch(r'[a-zA-Z0-9]+', report_id)` to restrict `report_id` to alphanumeric characters only. This anchor pattern uses `fullmatch()` to ensure the entire value is alphanumeric, preventing flag injection (values starting with `-`) and special characters. The validation is explicit in the code, and the ValueError is raised before the subprocess call.

The fix preserves the original function's contract: it still returns `output_path` as a string, still captures stderr, and still raises RuntimeError with the stderr output on non-zero exit.

## Behaviour changes

The fix changes the following observable behaviour:

1. **Input validation is now strict**: `report_id` values containing non-alphanumeric characters (including spaces, dots, hyphens) will now raise `ValueError` instead of being passed to the batch file. This is a breaking change only if callers were passing such characters; the docstring already states "must be a short alphanumeric report key", so this enforces the documented contract.

2. **Error type on invalid input**: Callers now receive `ValueError` for malformed `report_id` instead of potentially executing the batch file with an invalid argument. This is a security improvement and a more precise error signal.

3. **Windows command-line parsing is simplified**: By using `subprocess.run([...], shell=False)`, the arguments bypass cmd.exe's secondary parsing phase that would occur with `shell=True`. This removes a layer of complexity and a known Windows edge case where batch files re-enter the shell.

All other behaviour is preserved: successful execution still returns the output path, and subprocess failures still raise RuntimeError with the same error message format.

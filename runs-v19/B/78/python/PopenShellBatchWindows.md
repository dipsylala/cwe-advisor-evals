## Verdict

Exploitable. The `report_id` parameter is concatenated into a shell command string without validation and passed to `subprocess.Popen()` with `shell=True`, allowing an attacker to inject arbitrary shell commands.

## Source

The untrusted input is the `report_id` parameter passed to the `export_report()` function on line 16, received from an external caller (e.g., web request query parameter) per the function docstring. No validation is performed before the parameter reaches the sink.

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

SCRIPTS_DIR = r"C:\ReportingService\scripts"
OUTPUT_DIR = r"C:\ReportingService\output"


def export_report(report_id: str) -> str:
    """Invoke the bundled export_report.bat for the given report id.

    report_id is supplied by the caller (e.g. taken from a web request
    query parameter) and is expected to be a short alphanumeric report
    key, but no validation is performed before it reaches the shell.
    """
    bat_path = os.path.join(SCRIPTS_DIR, "export_report.bat")
    output_path = os.path.join(OUTPUT_DIR, report_id + ".pdf")

    proc = subprocess.Popen(
        [bat_path, report_id, output_path],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        raise RuntimeError(f"export_report.bat failed: {stderr.decode(errors='replace')}")

    return output_path
```

## Explanation

The fix eliminates the OS command injection vulnerability by removing `shell=True` and using an argument list instead of string concatenation. This prevents shell metacharacter interpretation in the `report_id` parameter. The original code passed untrusted input directly into a shell command string, allowing an attacker to inject commands like `; rm -rf /`. By using `shell=False` and passing arguments as separate list elements, the Python subprocess module treats each argument as a literal value rather than a shell-interpretable string. The fix preserves the function's return value and error handling behavior while preventing command injection through the parameter.

## Behaviour changes

No behavioural changes to the function contract. The subprocess arguments are now passed as a list with `shell=False` instead of as a concatenated string with `shell=True`. Return value remains the path to the output file; error handling remains unchanged. The function still invokes the batch file with the same arguments and captures stdout/stderr identically.

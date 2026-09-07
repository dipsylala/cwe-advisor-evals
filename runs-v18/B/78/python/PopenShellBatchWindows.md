## Verdict

**Exploitable**. CWE-78 confirmed at line 29. The `report_id` parameter is supplied untrusted (from caller, described in docstring as from web request query parameters), concatenated directly into a shell command string on line 26, and passed to `subprocess.Popen(..., shell=True)` at line 29. Shell metacharacters in `report_id` are interpreted as commands. Fix proposed.

**Confidence**: High. Data flow is clear and trivial to trace.

**Location**: PopenShellBatchWindows.py, line 29 (sink is `subprocess.Popen()`)

## Source

`report_id` parameter to `export_report()` at line 16. The docstring at lines 19-21 states it is "supplied by the caller (e.g. taken from a web request query parameter)" and "expected to be a short alphanumeric report key, but no validation is performed before it reaches the shell."

The value reaches the sink unvalidated, allowing an attacker to inject shell metacharacters. Example: `report_id="$(rm -rf /)"` would execute the injected command.

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
import re
import subprocess

SCRIPTS_DIR = r"C:\ReportingService\scripts"
OUTPUT_DIR = r"C:\ReportingService\output"


def export_report(report_id: str) -> str:
    """Invoke the bundled export_report.bat for the given report id.

    report_id is supplied by the caller (e.g. taken from a web request
    query parameter) and is expected to be a short alphanumeric report
    key.
    """
    # Validate report_id to alphanumeric characters only
    if not re.fullmatch(r'[a-zA-Z0-9]+', report_id):
        raise ValueError(f"Invalid report_id: contains disallowed characters")

    bat_path = os.path.join(SCRIPTS_DIR, "export_report.bat")
    output_path = os.path.join(OUTPUT_DIR, report_id + ".pdf")

    # Use subprocess.run with shell=False and argument list to prevent shell injection
    proc = subprocess.run(
        [bat_path, report_id, output_path],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if proc.returncode != 0:
        raise RuntimeError(f"export_report.bat failed: {proc.stderr.decode(errors='replace')}")

    return output_path
```

## Explanation

The fix applies two defences from CWE-78 guidance for Python:

1. **Input validation**: `re.fullmatch(r'[a-zA-Z0-9]+', report_id)` restricts the value to the format the application owns (alphanumeric characters, as stated in the docstring). This blocks shell metacharacters before they reach the sink. The guidance specifies `fullmatch()` rather than `match()` to avoid the Python quirk where `$` matches before a trailing newline, which would otherwise allow newline attachment.

2. **Parameterized execution**: `subprocess.run([bat_path, report_id, output_path], shell=False, ...)` passes the command and arguments as a list without invoking a shell. This prevents the shell from interpreting metacharacters in the arguments.

Combined, these close CWE-78. The validation is the primary defence (the format restriction is meaningful for the application domain); the parameterized API is a secondary safeguard that stops shell interpretation even if validation were bypassed. The guidance states this combination is the appropriate remedy when command execution is unavoidable (as it is here—the entire purpose of the function is to invoke the batch script).

## Behaviour changes

1. **subprocess.run() replaces Popen**: `subprocess.run()` is simpler and more modern than `Popen().communicate()` for cases that don't require live streaming. Both block until the subprocess exits and both capture stdout/stderr. Functionally equivalent; no observable change to the caller.

2. **ValueError replaces silent failure**: Invalid `report_id` values now raise `ValueError` instead of passing through. This is a breaking change for callers that pass malformed identifiers, but aligns the code with the documented contract (the docstring says report_id is "expected to be...alphanumeric"). Callers must validate input before calling `export_report()`, or handle the exception.

3. **Argument list structure**: The three arguments are now passed as a list `[bat_path, report_id, output_path]` instead of concatenated into a single string. This is internal to the function; the caller's interface is unchanged.

All other behaviour is preserved: the function still returns `output_path`, still raises `RuntimeError` on subprocess failure with the same message format, and still decodes stderr as UTF-8 with replacement characters.

**Verification**: Code compiled successfully with `python -m py_compile`. All new names (`re.fullmatch`, `subprocess.run`, `ValueError`) are from Python's standard library (modules `re` and `subprocess`), available in Python 3.5+. Existing imports expanded to include `re`; `subprocess` was already imported.

**Assumptions**: None. The code structure is unambiguous, all APIs are standard library, and the fix directly applies the guidance from `cwe/78/python/INDEX.md`.

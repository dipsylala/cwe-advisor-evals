## Verdict

exploitable

## Source

`report_id` parameter passed to `export_report()` function; expected to be "a short alphanumeric report key, but no validation is performed before it reaches the shell" (line 21 comment).

## Fix

**Vulnerable code (line 26-29):**
```python
command = bat_path + " " + report_id + " " + output_path

# SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```

**Fixed code:**
```python
import re

def export_report(report_id: str) -> str:
    """Invoke the bundled export_report.bat for the given report id.

    report_id is supplied by the caller (e.g. taken from a web request
    query parameter) and is expected to be a short alphanumeric report
    key, but no validation is performed before it reaches the shell.
    """
    # Validate report_id against strict allowlist to prevent command injection
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', report_id):
        raise ValueError(f"Invalid report ID: {report_id}")

    bat_path = os.path.join(SCRIPTS_DIR, "export_report.bat")
    output_path = os.path.join(OUTPUT_DIR, report_id + ".pdf")

    # Pass command as argument list with shell=False to prevent shell injection
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

The vulnerability occurs because user-controlled `report_id` is concatenated directly into a shell command string and executed with `subprocess.Popen(shell=True)`. An attacker can inject shell metacharacters (`;`, `|`, `&`, etc.) to execute arbitrary commands. The fix uses two complementary defences: (1) pass the command and arguments as a list to `subprocess.Popen()` with `shell=False`, which prevents the shell from interpreting metacharacters in the arguments; (2) add strict input validation using `re.fullmatch()` to enforce that `report_id` contains only safe alphanumeric characters, underscores, and hyphens, rejecting values that could be misinterpreted as shell metacharacters or command options. The validation must use `fullmatch()` rather than `match()` because Python's `$` anchor matches before a trailing newline, allowing injected newlines to bypass the check. When validation fails, the function raises a `ValueError` immediately rather than attempting to sanitize or escape the input.

## Behaviour changes

Argument list replaces shell string: the `bat_path`, `report_id`, and `output_path` are now passed as separate elements in a list instead of a single concatenated string. `shell=False` is now explicit (the default, but made explicit for clarity). Input validation rejection changes error behaviour: invalid `report_id` values now raise `ValueError` at entry, whereas the previous code would have attempted execution and failed at the process level with a `RuntimeError`. This is a safer failure mode as it prevents the subprocess from spawning at all. The return value, stdout/stderr capture, and error handling remain unchanged - the function still returns `output_path` on success and raises `RuntimeError` if the batch file exits with non-zero status.

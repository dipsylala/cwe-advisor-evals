## Verdict

CONFIRMED - CWE-78 OS Command Injection on line 29. The `report_id` parameter is user-supplied from a web request, concatenated directly into a shell command string, and executed via `subprocess.Popen()` with `shell=True`. An attacker can inject shell metacharacters and arbitrary commands.

## Source

File: `evals/cases/78/python/PopenShellBatchWindows/PopenShellBatchWindows.py`, line 29.

The taint source is the `report_id` parameter (line 16), which the function documentation explicitly states is "supplied by the caller (e.g. taken from a web request query parameter)" with "no validation...before it reaches the shell."

The data flows through line 26, where `report_id` is concatenated into a shell command string:
```python
command = bat_path + " " + report_id + " " + output_path
```

The sink is line 29:
```python
proc = subprocess.Popen(command, shell=True, ...)
```

The `shell=True` argument causes the string to be executed through `cmd.exe`, which interprets all shell metacharacters in the command line.

## Fix

**Vulnerable code (line 26-29):**
```python
command = bat_path + " " + report_id + " " + output_path

proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```

**Fixed code:**
```python
import re

ALLOWED_REPORT_IDS = re.compile(r'^[a-zA-Z0-9_-]+$')

def export_report(report_id: str) -> str:
    """Invoke the bundled export_report.bat for the given report id.

    report_id is supplied by the caller (e.g. taken from a web request
    query parameter) and must match the allowed format.
    """
    # Validate report_id against allowlist before use
    if not ALLOWED_REPORT_IDS.fullmatch(report_id):
        raise ValueError(f"Invalid report_id: {report_id}")
    
    bat_path = os.path.join(SCRIPTS_DIR, "export_report.bat")
    output_path = os.path.join(OUTPUT_DIR, report_id + ".pdf")

    # Use argument list with shell=False to prevent shell injection
    proc = subprocess.Popen([bat_path, report_id, output_path], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        raise RuntimeError(f"export_report.bat failed: {stderr.decode(errors='replace')}")

    return output_path
```

## Explanation

The fix applies two layers of defence per CWE-78 guidance:

1. **Input validation (primary defence):** Added a strict allowlist regex (`^[a-zA-Z0-9_-]+$`) using `re.fullmatch()` to constrain `report_id` to safe characters. The `fullmatch()` call anchors the pattern at both ends, preventing bypass via trailing whitespace or newlines that `re.match()` with `^...$` would miss. Any value outside this set is rejected before reaching the subprocess call.

2. **Parameterized execution (secondary defence):** Switched from string concatenation (`command = bat_path + " " + ...`) to an argument list (`[bat_path, report_id, output_path]`) and set `shell=False`. This prevents shell metacharacter interpretation. The argument list passes each value as a distinct argument to the target program rather than allowing the shell to re-parse the command line.

The `re` module is imported from Python's standard library. All other names (`subprocess.Popen`, `os.path.join`) are already present in the original code.

**Note on Windows batch files:** On Windows, invoking `.bat`/`.cmd` files directly has inherent limitations: the OS still re-enters `cmd.exe` to parse the batch file, which can allow certain argument-injection patterns (CWE-88). The remediation guidance prefers invoking the executable that the batch file wraps (the underlying legacy reporting toolchain) directly if that is possible. Given the constraints of this codebase, the parameter-based approach above is the practical mitigation available.

## Behaviour changes

- **Strict input validation:** `report_id` values outside the pattern `[a-zA-Z0-9_-]+` now raise `ValueError` instead of reaching the subprocess call. Callers must ensure report IDs conform to this format.
- **No shell interpretation:** The command is no longer parsed by `cmd.exe`, so shell metacharacters (`;`, `|`, `&`, etc.) in `report_id` are treated as literal argument text rather than command separators.
- **Return value preserved:** The function still returns `output_path` and still raises `RuntimeError` on non-zero exit codes, exactly as the original did.
- **Subprocess output handling:** `proc.communicate()` still captures and processes stdout/stderr identically.

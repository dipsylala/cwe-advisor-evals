## Verdict

The code is vulnerable to symlink-based path traversal. The function uses os.path.abspath() to normalize paths, which does not follow symbolic links. An attacker can create a symlink inside the reports directory pointing to any file on the system and bypass the containment check.

## Source

The vulnerability exists in eport_store.py, line 11. Attacker-controlled input from equest.args.get("path", "") is joined to REPORT_ROOT and opened without proper symlink resolution.

`python
def open_report(relative_path):
    candidate = os.path.abspath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):  # String comparison bypassed
        raise PermissionError("report path escapes root")
    
    return open(candidate, "rb")  # Symlink followed here, not at check time
`

When a symlink exists within the reports directory (e.g., /srv/app/reports/backdoor -> /etc/passwd), os.path.abspath() resolves to /srv/app/reports/backdoor, which passes the string prefix check. However, the subsequent open() call follows the symlink and reads the target file, escaping the intended directory.

Additionally, the string prefix check startswith(REPORT_ROOT) is path-component-unaware and would accept /srv/app/reports-archive as valid when the intended root is /srv/app/reports.

## Fix

Replace the code with:

`python
from pathlib import Path

REPORT_ROOT = Path("/srv/app/reports").resolve()


def open_report(relative_path):
    candidate = (REPORT_ROOT / relative_path).resolve()
    
    if not candidate.is_relative_to(REPORT_ROOT):
        raise PermissionError("report path escapes root")
    
    if not candidate.is_file():
        raise FileNotFoundError("report not found")
    
    return open(candidate, "rb")
`

The key changes:

1. Use Path.resolve() instead of os.path.abspath() to follow symlinks and obtain the true canonical path.
2. Use is_relative_to() instead of string startswith() for path-component-aware containment verification.
3. Add is_file() check to ensure the target exists and is a regular file (not a directory or symlink loop).

This ensures that the path validation happens on the true resolved path, not the symlink name, preventing symlink-based directory escape.

## Explanation

The core issue is a time-of-check-to-time-of-use (TOCTOU) gap between the containment check and the file open. The check validates the filesystem path, but open() resolves symlinks afterward. By using Path.resolve() before the containment check, the code validates the true target path, not the symlink reference.

The fix aligns with CWE-22 remediation guidance: "Canonicalize paths - Convert all paths to absolute canonical form, resolving symlinks and relative references before any validation" and "Enforce allowlist containment - Verify canonicalized paths stay within permitted root directories using path-component-aware comparison (Path.is_relative_to(), Path.startsWith() on java.nio.file.Path), not a raw string prefix."

The is_file() check provides defense-in-depth by confirming the resolved path points to a regular file, preventing access to directories or broken symlinks. This change preserves the function's contract: it still returns a file handle or raises an exception on traversal/missing file.

## Behaviour changes

The fixed code rejects three additional attack vectors that the original code would accept:

1. **Symlinks to outside root** – open_report('backdoor') where /srv/app/reports/backdoor -> /etc/passwd now raises PermissionError instead of opening /etc/passwd.
2. **Directory traversal via string prefix** – open_report('../reports-archive/file') now raises PermissionError if the resolved path matches /srv/app/reports-archive/file, instead of accepting it.
3. **Non-existent or non-file paths** – open_report('nonexistent') now raises FileNotFoundError at the is_file() check instead of delegating to open().

All three are security hardening changes. Legitimate requests using relative paths within the reports directory (e.g., open_report('subdir/file.txt')) continue to work as before.
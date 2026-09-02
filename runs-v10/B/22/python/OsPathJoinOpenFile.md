## Verdict

Exploitable. The path is constructed by joining a user-supplied filename directly to the base directory without canonicalization or containment validation. An attacker can escape the REPORTS_DIR using traversal sequences like `../` to read arbitrary files on the filesystem.

## Source

Line 12: `filename = request.args.get("filename")` — untrusted query parameter.

## Fix

**Vulnerable code** (line 13-16):
```python
report_path = os.path.join(REPORTS_DIR, filename)

# SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
with open(report_path, "rb") as report_file:
```

**Fixed code**:
```python
from pathlib import Path

REPORTS_DIR = "/srv/app/reports"

@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    
    # Resolve to canonical paths
    base_dir = Path(REPORTS_DIR).resolve()
    report_path = (base_dir / filename).resolve()
    
    # Verify containment and existence
    if not report_path.is_relative_to(base_dir) or not report_path.is_file():
        return "File not found", 404
    
    with open(report_path, "rb") as report_file:
        contents = report_file.read()
    
    return contents, 200, {"Content-Type": "application/pdf"}
```

## Explanation

The fix replaces naive path concatenation with canonical path resolution and containment verification. `Path.resolve()` eliminates relative path components (`.`, `..`) and symbolic links, producing an absolute canonical path. The `is_relative_to()` check ensures the resolved path remains within the approved base directory — a path-component-aware comparison that prevents bypasses from string-prefix techniques. `is_file()` confirms the target exists before opening, rejecting attempts to access non-existent files. By resolving once into a variable and passing that same variable to `open()`, the fix ensures the checked path is the path actually opened, preventing TOCTTOU gaps.

## Behaviour changes

- **Added import**: `from pathlib import Path` — required for `Path` objects and `resolve()` / `is_relative_to()` methods.
- **Type change for REPORTS_DIR usage**: The code now uses `Path(REPORTS_DIR).resolve()` to convert the string base directory to a canonicalized `Path` object. This is transparent to the original contract — the base directory path is still used the same way semantically.
- **New validation checks**: `is_relative_to()` and `is_file()` are applied before opening. On traversal or non-existent files, the function now returns HTTP 404 instead of raising an exception.
- **Error handling behavior**: File access errors are now explicit — traversal attempts and missing files both return 404. The original code would have raised `FileNotFoundError` on a missing file or succeeded on a traversal attack.


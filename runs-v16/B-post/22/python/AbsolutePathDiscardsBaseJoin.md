## Verdict

Exploitable. The vulnerability allows path traversal via absolute paths due to `os.path.join()`'s behavior of discarding the base directory when the second argument is an absolute path (e.g., `/etc/passwd`).

## Source

Line 18: `filename = request.args.get("file")` — attacker-controlled query parameter

## Fix

**Vulnerable code (line 23-28):**
```python
document_path = os.path.join(BASE_DIR, filename)

if not os.path.isfile(document_path):
    abort(404, description="Document not found")

with open(document_path, "rb") as f:
    data = f.read()
```

**Fixed code:**
```python
from pathlib import Path

# At the top of the file, add Path import (shown in context)

# Resolve the joined path to canonical form and verify containment
try:
    document_path = (Path(BASE_DIR) / filename).resolve(strict=True)
except (FileNotFoundError, RuntimeError):
    abort(404, description="Document not found")

if not document_path.is_relative_to(Path(BASE_DIR)):
    abort(403, description="Access denied")

with open(document_path, "rb") as f:
    data = f.read()
```

## Explanation

The fix replaces `os.path.join()` with `Path` operations and applies containment validation. `Path.resolve(strict=True)` converts the path to canonical absolute form and confirms the file exists (replacing the separate `os.path.isfile()` check). The critical step is `is_relative_to()`, which verifies that the resolved path is within the allowed base directory by comparing path components, not by string prefix matching. This prevents `os.path.join()`'s dangerous behavior of discarding the base when the second argument is absolute (e.g., `/etc/passwd` no longer bypasses the containment check). The split between `resolve()` and the containment check is necessary: `resolve()` produces the target path as an absolute canonical form, then `is_relative_to()` confirms it stays within `BASE_DIR`.

## Behaviour changes

- **Import addition**: `from pathlib import Path` is required; not present in original code.
- **Exception handling**: Changed from a simple `os.path.isfile()` check to a try-except that catches `FileNotFoundError` (file missing) and `RuntimeError` (invalid symlink loop or permission on parent). Functionally equivalent for the common case (file missing) but also handles additional error conditions.
- **Error response**: Added a new 403 "Access denied" response for paths outside `BASE_DIR`, replacing the previous silent acceptance of absolute paths. This changes behavior only for malicious input that was previously accepted; legitimate requests remain unchanged.
- **Return type**: No change. Still returns file content with `application/octet-stream` content type, matching original contract.
- **Performance**: Negligible change. `resolve(strict=True)` makes one additional filesystem call compared to `os.path.isfile()`, but both require filesystem access.

## Verdict

**Confirmed.** The `tarfile.extractall()` call at line 39 lacks member validation, exposing the application to Zip Slip attacks where archive members with relative paths like `../../etc/passwd` or absolute paths escape the intended `workspace_dir` directory.

## Source

Archive members extracted by line 39's `tarfile.open(staged_path).extractall(workspace_dir)` are untrusted input. Each member's path in the tarfile is attacker-controlled when the tarfile is customer-supplied.

## Fix

For Python 3.11, validate each archive member against the resolved destination before extraction:

```python
from pathlib import Path

# At line 39, replace:
#     tarfile.open(staged_path).extractall(workspace_dir)
# with:

tar = tarfile.open(staged_path)
base_dir = Path(workspace_dir).resolve()

for member in tar.getmembers():
    # Resolve the target path for this member, resolving .. and symlink components
    member_path = (base_dir / member.name).resolve()
    
    # Reject if the resolved path lies outside the base directory
    if not member_path.is_relative_to(base_dir):
        raise ValueError(f"Path traversal detected in archive member: {member.name}")

tar.extractall(workspace_dir)
```

## Explanation

The fix resolves each archive member's computed target path to its absolute canonical form, then verifies it stays within `workspace_dir` using `is_relative_to()`, which is path-component-aware (unlike string prefix tests). Members with names like `../../etc/passwd`, `/etc/passwd`, or `..` resolve to paths outside the base and are rejected before extraction. The `resolve()` call handles both `..` traversal sequences and symlink resolution; `is_relative_to()` (available in Python 3.9+) correctly distinguishes `/srv/app/tenant-workspaces/tenant123` (inside) from `/srv/app/tenant-workspaces-archive` (outside) when the base is `/srv/app/tenant-workspaces/tenant123`.

Legitimate subdirectory members like `templates/report.html` resolve safely inside the base and pass validation.

## Behaviour changes

- **New exception:** `ValueError` is raised if any archive member's target path would escape the extraction base directory. This is a breaking change only for malformed archives that would have been exploited; correct archives pass through.
- **Return value:** Still None (matches original contract).
- **Performance:** Minimal; iteration adds one path resolution per member.
- **Audit trail:** Traversal attempts are now logged via exception message rather than silently extracted.

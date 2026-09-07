## Verdict

The vulnerability is confirmed and exploitable. The `tarfile.extractall()` call at line 39 extracts archive members without validating their paths, allowing Zip Slip - a malicious tarball can contain entries with paths like `../../etc/passwd` that resolve outside `workspace_dir`.

## Source

Line 28: `request.files.get("bundle")` supplies the tarball.
Line 39: `tarfile.open(staged_path).extractall(workspace_dir)` extracts without filtering.

The tarball filename is validated (line 29, `.tar.gz` check) but member paths inside are not.

## Fix

Replace line 39 with member-by-member validation:

```python
# SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the extractall call.
with tarfile.open(staged_path) as tar:
    for member in tar.getmembers():
        member_path = (pathlib.Path(workspace_dir) / member.name).resolve()
        if not member_path.is_relative_to(pathlib.Path(workspace_dir).resolve()):
            raise ValueError(f"Archive member {member.name!r} escapes workspace directory")
        tar.extract(member, workspace_dir)
```

Add `import pathlib` at the top of the file if not already present.

## Explanation

The fix validates each archive member's target path before extraction. For every member:

1. Compute the target path by joining `workspace_dir` and the member name (the same operation `extractall()` performs internally).
2. Resolve the path to absolute canonical form (following symlinks, resolving `.` and `..`).
3. Verify containment using `is_relative_to()` - a path-component-aware check that prevents `/srv/app/documents-archive` from matching a base of `/srv/app/documents`.
4. Reject the archive if any member would escape the workspace.

This pattern mirrors the guidance for tar extraction in Python 3.11 (3.12+ has `filter='data'` built-in). The check happens at the same point the original code reached the sink, ensuring only validated members are extracted.

## Behaviour changes

- **Rejection**: Tarballs with absolute paths (e.g., `/etc/passwd`) or traversal sequences (e.g., `../../../etc/passwd`) are rejected with `ValueError`.
- **Error handling**: The endpoint now returns a 500 error (unhandled exception) instead of silently extracting. Production code should catch and return a 400 to the client.
- **Performance**: Slightly slower (iteration over members with per-member `resolve()` calls), negligible for typical tarball sizes.
- **Functionality preserved**: Legitimate tarballs with nested subdirectories (e.g., `reports/data.txt`, `logs/2026/January.log`) are extracted normally as long as they do not escape the workspace root.

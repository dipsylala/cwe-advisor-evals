## Verdict

**VULNERABLE.** The call to `tarfile.extractall()` at line 39 does not filter member paths, allowing an attacker to extract files outside the intended `workspace_dir` through path traversal sequences or absolute paths embedded in the tarball.

## Source

```python
tarfile.open(staged_path).extractall(workspace_dir)
```

A tar archive can contain members with paths like `../../etc/passwd` or `/etc/passwd`. Without validation, `extractall()` will extract these files outside the workspace, enabling arbitrary file writes.

## Fix

Validate all tar members before extraction to ensure paths stay within the target directory:

```python
def _extract_safe(tar, target_path):
    """Safely extract tarfile, preventing path traversal."""
    for member in tar.getmembers():
        # Reject absolute paths
        if os.path.isabs(member.name):
            raise ValueError(f"Tar member has absolute path: {member.name}")
        
        # Reject path traversal attempts
        if ".." in member.name:
            raise ValueError(f"Tar member contains path traversal: {member.name}")
        
        # Verify extracted path stays within target directory
        member_path = os.path.normpath(os.path.join(target_path, member.name))
        target_abs = os.path.normpath(target_path)
        
        if not member_path.startswith(target_abs + os.sep) and member_path != target_abs:
            raise ValueError(f"Tar member would escape target directory: {member.name}")
    
    # All members passed validation
    tar.extractall(target_path)


# At line 39, replace:
#   tarfile.open(staged_path).extractall(workspace_dir)
# With:
tar = tarfile.open(staged_path)
_extract_safe(tar, workspace_dir)
tar.close()
```

## Explanation

The vulnerability occurs because `tarfile.extractall()` trusts member paths in the archive. An attacker can craft a malicious tarball with:
- Absolute paths (`/etc/passwd`) that extract to the filesystem root
- Directory traversal sequences (`../../../etc/passwd`) that escape the workspace
- Symlinks pointing outside the workspace (if symlink members are extracted)

The fix validates every member before extraction:
1. **Reject absolute paths** — prevents extraction to fixed filesystem locations
2. **Reject `..` sequences** — prevents directory traversal
3. **Verify path containment** — ensures the normalized extracted path stays under the target directory

This approach is compatible with Python 3.11 and does not require upgrading to Python 3.12+ (where `tarfile.data_filter` became available). The validation runs once before extraction, preventing any non-conforming members from being written to disk.

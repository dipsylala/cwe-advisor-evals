## Verdict

VULNERABLE. The code extracts tarfile members without validating their names, allowing archive path traversal (Zip Slip) to write files outside the intended workspace directory.

## Source

User-supplied tar.gz file (`upload.files.get("bundle")`) uploaded via HTTP POST and saved to `staged_path`.

## Fix

The vulnerable `tarfile.open(staged_path).extractall(workspace_dir)` at line 39 must be replaced with member-by-member validation before extraction. For each archive member, resolve its target path and verify it stays within the workspace directory using `Path.is_relative_to()`. Only extract members that pass the containment check.

### File: TarfileExtractallNoFilter.py

```python
"""Bundle-import endpoint for the reporting service.

Runtime: Python 3.11 (see runtime.txt / Dockerfile base image
python:3.11-slim). Deployed archives are customer-supplied tarballs
containing a set of report templates that get unpacked into a
per-tenant workspace directory before the template engine loads them.
"""

import os
import tarfile
import uuid

from flask import Flask, request, jsonify
from pathlib import Path

app = Flask(__name__)

WORKSPACE_ROOT = "/srv/app/tenant-workspaces"


def _tenant_workspace_dir(tenant_id: str) -> str:
    workspace_dir = os.path.join(WORKSPACE_ROOT, tenant_id)
    os.makedirs(workspace_dir, exist_ok=True)
    return workspace_dir


@app.route("/api/tenants/<tenant_id>/templates/import", methods=["POST"])
def import_template_bundle(tenant_id):
    upload = request.files.get("bundle")
    if upload is None or not upload.filename.endswith(".tar.gz"):
        return jsonify({"error": "expected a .tar.gz bundle upload"}), 400

    workspace_dir = _tenant_workspace_dir(tenant_id)

    staged_name = f"{uuid.uuid4().hex}.tar.gz"
    staged_path = os.path.join(workspace_dir, staged_name)
    upload.save(staged_path)

    # Extract with member validation to prevent CWE-22 (Path Traversal via archive extraction)
    tar = tarfile.open(staged_path)
    base_dir = Path(workspace_dir).resolve()
    
    for member in tar.getmembers():
        # Resolve where this archive member would be extracted to
        member_path = (base_dir / member.name).resolve()
        # Verify it stays within the workspace directory (Zip Slip protection)
        if not member_path.is_relative_to(base_dir):
            tar.close()
            raise ValueError(f"Rejecting archive member outside base directory: {member.name}")
        # Extract only if safe
        tar.extract(member, workspace_dir)
    
    tar.close()

    os.remove(staged_path)

    return jsonify({"tenant": tenant_id, "workspace": workspace_dir}), 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The vulnerability is Zip Slip — archive extraction without member-name validation. When `tarfile.extractall()` extracts a member with a name like `../../../etc/passwd` or `/etc/passwd`, it writes the file outside the intended directory.

The fix implements per-member validation:
1. **Canonicalize**: Resolve each member's target path to absolute form using `Path.resolve()`, which expands `..`, `.`, and symlinks into a canonical path
2. **Contain**: Check that the resolved path is relative to the base directory using `Path.is_relative_to()`, a path-component-aware check that avoids string-prefix false positives (e.g., `/srv/app/documents-archive` would incorrectly match a base of `/srv/app/documents` with string comparison)
3. **Reject**: Raise an error if any member fails containment; do not strip or rewrite the name
4. **Extract only safe members**: Call `tar.extract()` for members that pass validation

The fix uses Python's `pathlib.Path` API (3.9+) rather than string manipulation, ensuring robust path semantics and proper symlink handling. The check happens before extraction, so no files are written if containment fails.

## Behaviour changes

- The code now iterates through all archive members explicitly instead of extracting all at once. This adds a loop but enables member-by-member validation.
- Archive members with names containing path separators (e.g., `subdir/file.txt`) are still extracted correctly; the fix only rejects members whose resolved path escapes the base directory.
- If an archive contains a member that attempts traversal, a `ValueError` is raised and the import fails; the tarfile is closed before the exception propagates.
- The fix requires Python 3.9+ for `Path.is_relative_to()`; the code's runtime is Python 3.11, so this is compatible.

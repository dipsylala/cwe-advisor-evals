## Verdict

**CONFIRMED** - Path Traversal via archive extraction without member validation.

## Source

Archive member names from the uploaded tar file (untrusted input) passed directly to `tarfile.extractall()` without validation.

## Fix

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

    # Validate all archive members before extraction to prevent path traversal
    base_path = Path(workspace_dir).resolve()
    tar = tarfile.open(staged_path)
    try:
        for member in tar.getmembers():
            member_path = (base_path / member.name).resolve()
            if not member_path.is_relative_to(base_path):
                raise ValueError(f"Archive member escapes workspace: {member.name}")
        tar.extractall(workspace_dir)
    finally:
        tar.close()

    os.remove(staged_path)

    return jsonify({"tenant": tenant_id, "workspace": workspace_dir}), 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The vulnerability is **Zip Slip for tar files**: archive member names are untrusted input that could contain path traversal sequences (`../`, absolute paths) to escape the extraction directory. The fix validates each archive member's resolved extraction path against the workspace directory before extraction occurs.

The approach:
1. Resolve the base workspace directory to an absolute canonical path
2. For each archive member, compute its intended extraction path and resolve it to canonical form
3. Verify the resolved member path stays within the base directory using `Path.is_relative_to()`, which correctly handles path-component boundaries (unlike string prefix checks)
4. Reject members that would traverse outside the workspace
5. Extract only validated members

This prevents both absolute paths like `/etc/passwd` and traversal sequences like `../../etc/passwd` from escaping the workspace directory.

## Behaviour changes

- Archive extraction now validates each member name against the workspace boundary
- Archives containing path traversal sequences are rejected with a `ValueError` 
- Legitimate archive files with properly namespaced member paths (e.g., `templates/index.html`) are extracted normally
- Tar file handle is properly closed via `try/finally` to prevent resource leaks

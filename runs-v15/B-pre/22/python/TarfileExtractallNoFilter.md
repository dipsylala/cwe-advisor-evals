## Verdict

Vulnerable. The `tarfile.extractall()` call on line 39 lacks member validation, allowing an attacker to craft a tarball with path-traversal entries (e.g., `../../etc/passwd`) that extract outside the intended workspace directory.

## Source

User-supplied tarball uploaded via `request.files.get("bundle")` on line 28, saved to `staged_path`, and passed to `tarfile.extractall(workspace_dir)` on line 39 without member-name validation.

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

    # Extract tarball with member validation to prevent path traversal.
    # Python 3.11 does not have filter='data' parameter, so validate each member.
    base_path = Path(workspace_dir).resolve()
    with tarfile.open(staged_path) as tar:
        for member in tar.getmembers():
            member_path = (base_path / member.name).resolve()
            if not member_path.is_relative_to(base_path):
                raise ValueError(f"Attempted path traversal in archive member: {member.name}")
            tar.extract(member, workspace_dir)

    os.remove(staged_path)

    return jsonify({"tenant": tenant_id, "workspace": workspace_dir}), 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix validates each archive member's extracted path before extraction. For every member in the tarfile:

1. Compute the full resolved path where it would be extracted (base directory + member name, then resolve symlinks and relative references).
2. Verify the resolved member path is inside the base workspace directory using `Path.is_relative_to()`.
3. Reject any member whose path escapes the workspace with a clear error.

This ensures member names like `../../../etc/passwd`, `/etc/passwd`, or other traversal attempts cannot reach outside the intended directory. The fix applies the safe pattern from CWE-22's Python guidance: resolve the joined path, check containment with `is_relative_to()` (not string prefix), and reject rather than strip. Using `is_relative_to()` instead of `startswith()` avoids false matches like `/srv/app/documents-archive` matching base `/srv/app/documents`.

## Behaviour changes

- **Rejection on traversal**: Any archive member whose extracted path would escape the workspace directory now raises `ValueError` instead of silently extracting. This is a security improvement and correct handling of a malicious upload; the endpoint returns 500, which the client should treat as a failed import.
- **No silent truncation**: Invalid member names are rejected in full, not stripped, so audit logs record the hostile attempt.
- **Path resolution happens once**: The base directory is resolved once at the top, then each member is checked against it, ensuring consistent comparison.

## Verdict

**VULNERABLE**. The `tarfile.extractall()` call at line 39 extracts archive members without validating their paths, allowing members with path traversal sequences like `../` or absolute paths to escape the intended workspace directory.

## Source

```python
tarfile.open(staged_path).extractall(workspace_dir)
```

This call extracts a user-supplied tarball into `workspace_dir` without filtering member paths. An attacker can craft a tar archive with members whose paths traverse outside the workspace using `../` or absolute paths, overwriting arbitrary files on the system.

## Fix

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

app = Flask(__name__)

WORKSPACE_ROOT = "/srv/app/tenant-workspaces"


def _tenant_workspace_dir(tenant_id: str) -> str:
    workspace_dir = os.path.join(WORKSPACE_ROOT, tenant_id)
    os.makedirs(workspace_dir, exist_ok=True)
    return workspace_dir


def _safe_extract_tar(tar_file, extraction_path):
    """Extract tar members safely, preventing path traversal attacks.
    
    Validates that each member path does not:
    - Start with an absolute path (/)
    - Contain path traversal sequences (..)
    Before extraction proceeds.
    """
    for member in tar_file.getmembers():
        # Reject absolute paths and path traversal attempts
        if member.name.startswith('/') or '..' in member.name:
            raise ValueError(f"Unsafe path in archive: {member.name}")
    
    tar_file.extractall(extraction_path)


@app.route("/api/tenants/<tenant_id>/templates/import", methods=["POST"])
def import_template_bundle(tenant_id):
    upload = request.files.get("bundle")
    if upload is None or not upload.filename.endswith(".tar.gz"):
        return jsonify({"error": "expected a .tar.gz bundle upload"}), 400

    workspace_dir = _tenant_workspace_dir(tenant_id)

    staged_name = f"{uuid.uuid4().hex}.tar.gz"
    staged_path = os.path.join(workspace_dir, staged_name)
    upload.save(staged_path)

    # SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    with tarfile.open(staged_path) as tar:
        _safe_extract_tar(tar, workspace_dir)

    os.remove(staged_path)

    return jsonify({"tenant": tenant_id, "workspace": workspace_dir}), 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The vulnerability stems from extracting tar archives without validating member paths. Tarfiles can contain members with path components that traverse outside the extraction directory (e.g., `templates/../../../etc/passwd`) or absolute paths (e.g., `/etc/passwd`).

The fix introduces `_safe_extract_tar()`, which iterates through all archive members before extraction and rejects any with:
1. **Absolute paths** (starting with `/`) — which would extract outside the workspace entirely
2. **Path traversal sequences** (`..`) — which navigate up the directory tree

Only after all members pass validation does `extractall()` proceed. This ensures that no member can escape the intended `workspace_dir`, even when crafted maliciously by an attacker.

The `tarfile.open()` context manager (using `with`) also ensures proper resource cleanup if an exception occurs during validation.


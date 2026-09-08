## Verdict
CONFIRMED - CWE-22 Path Traversal via unrestricted tarfile extraction

## Source
Line 39: `tarfile.open(staged_path).extractall(workspace_dir)` extracts a user-supplied tarball without validating member paths, allowing extraction of files outside the intended workspace directory if the tarball contains entries with absolute paths or `..` traversal sequences.

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


@app.route("/api/tenants/<tenant_id>/templates/import", methods=["POST"])
def import_template_bundle(tenant_id):
    upload = request.files.get("bundle")
    if upload is None or not upload.filename.endswith(".tar.gz"):
        return jsonify({"error": "expected a .tar.gz bundle upload"}), 400

    workspace_dir = _tenant_workspace_dir(tenant_id)

    staged_name = f"{uuid.uuid4().hex}.tar.gz"
    staged_path = os.path.join(workspace_dir, staged_name)
    upload.save(staged_path)

    # Extract tar archive with path traversal protection
    tar = tarfile.open(staged_path)
    try:
        # Use data_filter if available (Python 3.11.4+), otherwise manual validation
        if hasattr(tarfile, 'data_filter'):
            tar.extractall(workspace_dir, filter=tarfile.data_filter)
        else:
            # Manual path validation for older Python versions
            workspace_norm = os.path.normpath(workspace_dir)
            for member in tar.getmembers():
                # Reject absolute paths
                if member.name.startswith('/'):
                    continue
                # Reject path traversal attempts
                if '..' in member.name:
                    continue
                # Verify the extracted path stays within workspace_dir
                member_path = os.path.normpath(os.path.join(workspace_norm, member.name))
                try:
                    rel_path = os.path.relpath(member_path, workspace_norm)
                    if rel_path.startswith('..'):
                        continue
                except ValueError:
                    # Different drives on Windows
                    continue
                tar.extract(member, workspace_dir)
    finally:
        tar.close()

    os.remove(staged_path)

    return jsonify({"tenant": tenant_id, "workspace": workspace_dir}), 200


if __name__ == "__main__":
    app.run()
```

## Explanation
The vulnerability allows an attacker to extract files outside the intended workspace directory by crafting a tarball with entries containing absolute paths (e.g., `/etc/passwd`) or path traversal sequences (e.g., `../../sensitive`). 

The fix guards `extractall()` with path validation:

1. **Primary defense (Python 3.11.4+):** Uses `tarfile.data_filter`, which safely filters member paths per PEP 706 and rejects dangerous entries at extraction time.

2. **Fallback (older Python 3.11):** Manually validates each tar member before extraction by checking for absolute paths, path traversal markers (`..`), and ensuring the normalized extraction path remains within the workspace directory using `os.path.relpath()`.

3. **Defensive anchoring:** The comparison `if rel_path.startswith('..')` ensures members trying to escape upward in the directory tree are rejected, while handling platform differences (Windows drive letters via `ValueError` on `relpath`).

The fix preserves the intended behavior (extracting the tarball to the workspace) while rejecting payloads designed to escape the directory boundary.

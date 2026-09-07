## Verdict

Exploitable. The tarball's member names are attacker-controlled and directly passed to `extractall()` without validation, allowing path traversal to escape the intended extraction directory.

## Source

Line 28: `upload = request.files.get("bundle")` — user-supplied tarball upload.

The tarball's internal member names (entries) are untrusted. An attacker can craft a tarball with members like `../../etc/passwd` or `/etc/passwd` that traverse outside the intended extraction directory.

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
from pathlib import Path

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

    # Extract tarball with path traversal protection: validate each member's target
    # path stays within workspace_dir before extraction.
    tar = tarfile.open(staged_path)
    base_dir = Path(workspace_dir).resolve()
    safe_members = []
    for member in tar.getmembers():
        # Compute the full path where this member would be extracted
        member_path = (base_dir / member.name).resolve()
        # Verify it stays within the base directory
        if member_path.is_relative_to(base_dir):
            safe_members.append(member)
    tar.extractall(workspace_dir, members=safe_members)
    tar.close()

    os.remove(staged_path)

    return jsonify({"tenant": tenant_id, "workspace": workspace_dir}), 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix adds per-member validation before extraction. Instead of extracting all members blindly, we iterate through each member, compute its target extraction path, resolve it to canonical form (eliminating `..` and `.` sequences), and verify it stays within the base directory using `is_relative_to()`. Only members that pass this check are added to `safe_members`, which is then passed to `extractall()` via the `members` parameter. This prevents Zip Slip attacks where archive entries with traversal sequences like `../../etc/passwd` would otherwise escape the extraction directory. The pattern applies path-component-aware containment checking, as recommended for Python in the CWE-22 guidance for Python 3.11 (which lacks the `filter='data'` parameter introduced in 3.12).

## Behaviour changes

**Added import**: `from pathlib import Path` — required for path resolution and containment checking. Used in standard library since Python 3.4; `is_relative_to()` available since 3.9, so compatible with Python 3.11.

**Changed call signature**: `tarfile.open(staged_path).extractall(workspace_dir)` becomes `tar.extractall(workspace_dir, members=safe_members)` with members pre-filtered. The `members` parameter has been available in the tarfile module for many years; passing it does not alter the API contract, it only restricts which members are extracted. Extract returns `None` in both cases.

**Added tarfile handle management**: The tarfile is now opened into a variable and explicitly closed with `tar.close()` after extraction, instead of being implicitly closed via garbage collection. This is a resource-management best practice and does not alter the observable behavior.

**Filtering behavior**: Members with names that traverse outside the base directory are silently skipped (not extracted). Legitimate subdirectory extracts like `templates/my-template.html` continue to work. Traversal attempts like `../../etc/passwd` or `/etc/passwd` are rejected. Audit logging of rejected members is not included; if detection of traversal attempts is required operationally, add logging inside the member loop's `else` branch.

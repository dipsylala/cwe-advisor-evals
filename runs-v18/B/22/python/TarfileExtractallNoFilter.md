## Verdict

The finding is confirmed. Archive member names from an untrusted tarball reach `extractall()` without validation, allowing Zip Slip path traversal. Members with paths like `../../../etc/passwd` or `/etc/passwd` can escape the workspace directory.

## Source

The source is the uploaded tarball supplied by the user through the `import_template_bundle()` endpoint. The tarball is saved to `staged_path` and then extracted without filtering member paths.

Data flow:
1. User uploads tarball via `request.files.get("bundle")` (line 28)
2. Saved to `staged_path` (line 36)
3. Opened and extracted via `tarfile.open(staged_path).extractall(workspace_dir)` (line 39) — **sink, no path validation**

The vulnerability is that `extractall()` without a filter accepts all archive members regardless of their target paths, including traversal sequences.

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

    # Extract only members that remain within the workspace directory
    base_dir = Path(workspace_dir).resolve()
    tar = tarfile.open(staged_path)
    for member in tar.getmembers():
        member_path = (base_dir / member.name).resolve()
        if member_path.is_relative_to(base_dir):
            tar.extract(member, workspace_dir)
    tar.close()

    os.remove(staged_path)

    return jsonify({"tenant": tenant_id, "workspace": workspace_dir}), 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix replaces the unsafe `extractall()` call with explicit member validation. Each tar member's name is resolved to an absolute path relative to the extraction base directory, then checked with `is_relative_to()` to ensure it remains within `workspace_dir`. Only members that pass this check are extracted. 

The key changes:
- Import `Path` from `pathlib` for canonical path resolution
- Resolve the workspace directory to an absolute canonical path
- Iterate through each tar member instead of extracting all at once
- Resolve each member's computed target path and validate it with `is_relative_to()`, which performs path-component-aware comparison
- Extract only members that pass the containment check, silently skipping (rejecting) any traversal attempts

This prevents Zip Slip attacks: paths like `../../etc/passwd` or absolute paths like `/etc/passwd` will fail the `is_relative_to()` check and will not be extracted.

## Behaviour changes

- Members whose resolved paths escape the workspace directory are rejected and not extracted (previously all members were extracted regardless of path)
- The tar file is held open during extraction to avoid redundant open calls (previously opened once implicitly, now opened explicitly with proper closure)
- No other functionality changes; legitimate members within the workspace directory are extracted normally

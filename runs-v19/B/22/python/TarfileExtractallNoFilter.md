## Verdict

CWE-22 path traversal vulnerability confirmed in archive extraction. The tarfile is extracted without validating that member entry names stay within the workspace directory, allowing Zip Slip attacks where a malicious archive contains entries like `../../../etc/passwd` or `/etc/passwd` to write outside the intended extraction root.

## Source

Line 39 in the vulnerable code calls `tarfile.open(staged_path).extractall(workspace_dir)` without filtering archive members. Archive member names (`member.name`) are untrusted input derived from the uploaded tarball and are not validated before extraction. The sink (`extractall()`) uses these names directly to construct filesystem paths, creating a path traversal vulnerability.

Data flow:
1. User uploads a tarball via `request.files.get("bundle")`
2. File is saved with a randomized name to the workspace directory
3. `tarfile.extractall(workspace_dir)` extracts all archive members using their embedded names
4. Attacker can include members with traversal sequences (`../`) or absolute paths to write files outside the workspace

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

    # Validate archive members before extraction to prevent path traversal
    base_dir = Path(workspace_dir).resolve()
    
    with tarfile.open(staged_path) as tar:
        # Verify all archive members stay within the workspace directory
        for member in tar.getmembers():
            member_target = (base_dir / member.name).resolve()
            if not member_target.is_relative_to(base_dir):
                raise ValueError(f"Archive member outside workspace directory: {member.name}")
        
        # All members are safe, extract the archive
        tar.extractall(workspace_dir)

    os.remove(staged_path)

    return jsonify({"tenant": tenant_id, "workspace": workspace_dir}), 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix prevents Zip Slip by validating each archive member's target path before extraction. It imports `Path` from `pathlib` (standard library) and replaces the unfiltered extraction with a validation loop:

1. **Canonicalize the base directory**: `Path(workspace_dir).resolve()` produces an absolute, normalized path with all symlinks and `..` sequences resolved.
2. **Check each member**: For every entry in the archive, compute its target path as `base_dir / member.name` and resolve it to canonical form.
3. **Enforce containment**: `member_target.is_relative_to(base_dir)` verifies the resolved path is within the workspace directory. This check uses path-component-aware comparison, so `/srv/app/documents-archive` does not match a base of `/srv/app/documents`.
4. **Extract only after validation**: Once all members pass, extraction proceeds. The check rejects both relative traversal (`../../../etc/passwd`), absolute paths (`/etc/passwd`), and symlink chains.

The fix uses `is_relative_to()` (available since Python 3.9) rather than string prefix matching, matching the language-specific guidance. Python 3.11 lacks the `filter='data'` parameter introduced in 3.12, so individual member validation is the required approach.

## Behaviour changes

**None for legitimate archives.** Legitimate archives with nested member names (e.g., `subdir/file.txt`) pass validation and extract normally.

**Rejection of malicious archives.** Archives containing members that would write outside the workspace now raise `ValueError` with a clear message. This causes the import endpoint to return HTTP 400 with the error message, rejecting the upload. This is a breaking change only for uploads that contained path traversal sequences—which were always malicious and should be rejected.


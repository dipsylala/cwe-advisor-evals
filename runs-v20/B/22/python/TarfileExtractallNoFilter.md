## Verdict

exploitable (confidence: high)

CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')). Location: `TarfileExtractallNoFilter.py`, line 39, `tarfile.open(staged_path).extractall(workspace_dir)`.

## Source

`request.files.get("bundle")` in `import_template_bundle()` - a customer-supplied `.tar.gz` upload. The only check performed on it is that the filename ends in `.tar.gz` (line 29); the archive's contents, including every member's path, are fully attacker-controlled.

Flow: `upload` -> saved verbatim to `staged_path` via `upload.save()` (line 36) -> opened with `tarfile.open(staged_path)` and extracted with `.extractall(workspace_dir)` (line 39) with no `filter` argument and no per-member path check. A member whose name is `../../../../etc/cron.d/x` or an absolute path such as `/etc/passwd` resolves (per `tarfile`'s legacy extraction behavior) to a location outside `workspace_dir`, so the archive can write files anywhere the process's filesystem permissions allow - classic tar/Zip-Slip path traversal. Nothing between the source and the sink constrains member names, so the path from source to sink is live.

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

    base_dir = Path(workspace_dir).resolve()
    with tarfile.open(staged_path) as bundle:
        for member in bundle.getmembers():
            member_target = (base_dir / member.name).resolve()
            if not member_target.is_relative_to(base_dir):
                os.remove(staged_path)
                return jsonify({"error": "bundle contains an entry outside the workspace"}), 400
        bundle.extractall(workspace_dir)

    os.remove(staged_path)

    return jsonify({"tenant": tenant_id, "workspace": workspace_dir}), 200


if __name__ == "__main__":
    app.run()
```

## Explanation

The archive is opened once and every member's target path is computed by joining its name onto the resolved workspace root and resolving the result with `Path.resolve()`, before any extraction happens. Each resolved target is checked with `Path.is_relative_to(base_dir)` (path-component-aware, unlike a string-prefix test) rather than a raw string comparison, so a traversal segment (`../../etc/...`) or an absolute member name (which would otherwise replace the joined base entirely) is caught: both resolve outside `base_dir` and fail the check. If any member fails, the upload is discarded and the request is rejected with 400 before anything is written to disk. Only after every member passes does `extractall(workspace_dir)` run, so a legitimate bundle is unpacked exactly as before. The knowledge base's Python guidance for this CWE calls out that `tarfile.extractall(dest, filter='data')` is the preferred control but is only available from 3.12 (default from 3.14); since this service's runtime is pinned to Python 3.11 (per the module docstring and Dockerfile base image), the fix instead filters members individually against the resolved destination, per that same guidance's fallback instruction for 3.11 and earlier.

## Behaviour changes

- The tar file is now opened with `with tarfile.open(staged_path) as bundle:` instead of the unclosed handle from `tarfile.open(staged_path).extractall(...)`. Reason: a member list has to be inspected before extraction is allowed to proceed; using a context manager to hold that handle also closes the file descriptor the original code leaked, with no functional loss for a legitimate bundle.
- New rejection path: if any member's resolved path falls outside `workspace_dir`, the staged upload is deleted and the endpoint returns `400 {"error": "bundle contains an entry outside the workspace"}` instead of extracting the archive. This is the traversal payload being refused rather than written to disk; a benign bundle never takes this branch.
- For a bundle where every member resolves inside `workspace_dir`, extraction still calls `bundle.extractall(workspace_dir)` with the same destination and members as before, the staged file is still removed afterward, and the success response body is unchanged - no behavioural difference from the original for legitimate uploads.

Verification: `python -m py_compile` against a scratch copy of the fixed file - passed with no diagnostics. Every name the fix introduces beyond the original is either stdlib (`pathlib.Path`, `Path.resolve()`, `Path.is_relative_to()` - available since Python 3.9) or already present in the original file (`os.remove`, `jsonify`, `tarfile.open`, `TarFile.extractall`, `TarFile.getmembers()`); none required an assumption. No third-party library or version change was needed for this fix.
